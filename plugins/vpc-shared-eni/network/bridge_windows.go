// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package network

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/hns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	"github.com/Microsoft/hcsshim"
	log "github.com/cihub/seelog"
)

const (
	// hnsL2Bridge is the HNS network type used by this plugin on Windows.
	hnsL2Bridge = "l2bridge"

	// hnsNetworkNameFormat is the format used for generating bridge names (e.g. "vpcbr1").
	hnsNetworkNameFormat = "%sbr%s"

	// hnsEndpointNameFormat is the format of the names generated for HNS endpoints.
	hnsEndpointNameFormat = "cid-%s"
)

var (
	// hnsMinVersion is the minimum version of HNS supported by this plugin.
	hnsMinVersion = hcsshim.HNSVersion1803
)

// hnsRoutePolicy is an HNS route policy.
// This definition really needs to be in Microsoft's hcsshim package.
type hnsRoutePolicy struct {
	hcsshim.Policy
	DestinationPrefix string `json:"DestinationPrefix,omitempty"`
	NeedEncap         bool   `json:"NeedEncap,omitempty"`
}

// BridgeBuilder implements NetworkBuilder interface by bridging containers to an ENI on Windows.
type BridgeBuilder struct{}

// FindOrCreateNetwork creates a new HNS network.
func (nb *BridgeBuilder) FindOrCreateNetwork(nw *Network) error {
	// Check that the HNS version is supported.
	err := nb.checkHNSVersion()
	if err != nil {
		return err
	}

	// HNS API does not support creating virtual switches in compartments other than the host's.
	if nw.BridgeNetNSPath != "" {
		return fmt.Errorf("Bridge must be in host network namespace on Windows")
	}

	// Check if the network already exists.
	networkName := nb.generateHNSNetworkName(nw)
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err == nil {
		log.Infof("Found existing HNS network %s.", networkName)
		return nil
	}

	// Initialize the HNS network.
	hnsNetwork = &hcsshim.HNSNetwork{
		Name:               networkName,
		Type:               hnsL2Bridge,
		NetworkAdapterName: nw.SharedENI.GetLinkName(),

		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  vpc.GetSubnetPrefix(&nw.ENIIPAddresses[0]).String(),
				GatewayAddress: nw.GatewayIPAddress.String(),
			},
		},
	}

	buf, err := json.Marshal(hnsNetwork)
	if err != nil {
		return err
	}
	hnsRequest := string(buf)

	// Create the HNS network.
	log.Infof("Creating HNS network: %+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest)
	if err != nil {
		log.Errorf("Failed to create HNS network: %v.", err)
		return err
	}

	log.Infof("Received HNS network response: %+v.", hnsResponse)

	return nil
}

// DeleteNetwork deletes an existing HNS network.
func (nb *BridgeBuilder) DeleteNetwork(nw *Network) error {
	// Find the HNS network ID.
	networkName := nb.generateHNSNetworkName(nw)
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return err
	}

	// Delete the HNS network.
	log.Infof("Deleting HNS network name: %s ID: %s", networkName, hnsNetwork.Id)
	_, err = hcsshim.HNSNetworkRequest("DELETE", hnsNetwork.Id, "")
	if err != nil {
		log.Errorf("Failed to delete HNS network: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint creates a new HNS endpoint in the network.
func (nb *BridgeBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// This plugin does not yet support IPv6, or multiple IPv4 addresses.
	if len(ep.IPAddresses) > 1 || ep.IPAddresses[0].IP.To4() == nil {
		return fmt.Errorf("Only a single IPv4 address per endpoint is supported on Windows")
	}

	// Query the namespace identifier.
	nsType, namespaceIdentifier := hns.GetNamespaceIdentifier(ep.NetNSName, ep.ContainerID)

	// Check if the endpoint already exists.
	endpointName := nb.generateHNSEndpointName(ep, namespaceIdentifier)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err == nil {
		log.Infof("Found existing HNS endpoint %s.", endpointName)
		if nsType == hns.InfraContainerNS || nsType == hns.HcnNamespace {
			// This is a benign duplicate create call for an existing endpoint.
			// The endpoint was already attached in a previous call. Ignore and return success.
			log.Infof("HNS endpoint %s is already attached to container ID %s.",
				endpointName, ep.ContainerID)
		} else {
			// Attach the existing endpoint to the container's network namespace.
			err = hns.AttachEndpoint(hnsEndpoint, nsType, ep.ContainerID, namespaceIdentifier)
		}

		ep.MACAddress, _ = net.ParseMAC(hnsEndpoint.MacAddress)
		return err
	} else {
		if nsType != hns.InfraContainerNS && nsType != hns.HcnNamespace {
			// The endpoint referenced in the container netns does not exist.
			log.Errorf("Failed to find endpoint %s for container %s.", endpointName, ep.ContainerID)
			return fmt.Errorf("failed to find endpoint %s: %v", endpointName, err)
		}
	}

	// Initialize the HNS endpoint.
	hnsEndpoint = &hcsshim.HNSEndpoint{
		Name:               endpointName,
		VirtualNetworkName: nb.generateHNSNetworkName(nw),
		DNSSuffix:          strings.Join(nw.DNSSuffixSearchList, ","),
		DNSServerList:      strings.Join(nw.DNSServers, ","),
	}

	// Set the endpoint IP address.
	hnsEndpoint.IPAddress = ep.IPAddresses[0].IP
	pl, _ := ep.IPAddresses[0].Mask.Size()
	hnsEndpoint.PrefixLength = uint8(pl)

	// SNAT endpoint traffic to ENI primary IP address...
	var snatExceptions []string
	if nw.VPCCIDRs == nil {
		// ...except if the destination is in the same subnet as the ENI.
		snatExceptions = []string{vpc.GetSubnetPrefix(&nw.ENIIPAddresses[0]).String()}
	} else {
		// ...or, if known, the same VPC.
		for _, cidr := range nw.VPCCIDRs {
			snatExceptions = append(snatExceptions, cidr.String())
		}
	}
	if nw.ServiceCIDR != "" {
		// ...or the destination is a service endpoint.
		snatExceptions = append(snatExceptions, nw.ServiceCIDR)
	}

	err = nb.addEndpointPolicy(
		hnsEndpoint,
		hcsshim.OutboundNatPolicy{
			Policy: hcsshim.Policy{Type: hcsshim.OutboundNat},
			// Implicit VIP: nw.ENIIPAddresses[0].IP.String(),
			Exceptions: snatExceptions,
		})
	if err != nil {
		log.Errorf("Failed to add endpoint SNAT policy: %v.", err)
		return err
	}

	// Route traffic sent to service endpoints to the host. The load balancer running
	// in the host network namespace then forwards traffic to its final destination.
	if nw.ServiceCIDR != "" {
		// Set route policy for service subnet.
		// NextHop is implicitly the host.
		err = nb.addEndpointPolicy(
			hnsEndpoint,
			hnsRoutePolicy{
				Policy:            hcsshim.Policy{Type: hcsshim.Route},
				DestinationPrefix: nw.ServiceCIDR,
				NeedEncap:         true,
			})
		if err != nil {
			log.Errorf("Failed to add endpoint route policy for service subnet: %v.", err)
			return err
		}

		// Set route policy for host primary IP address.
		err = nb.addEndpointPolicy(
			hnsEndpoint,
			hnsRoutePolicy{
				Policy:            hcsshim.Policy{Type: hcsshim.Route},
				DestinationPrefix: nw.ENIIPAddresses[0].IP.String() + "/32",
				NeedEncap:         true,
			})
		if err != nil {
			log.Errorf("Failed to add endpoint route policy for host: %v.", err)
			return err
		}
	}

	// Encode the endpoint request.
	buf, err := json.Marshal(hnsEndpoint)
	if err != nil {
		return err
	}
	hnsRequest := string(buf)

	// Create the HNS endpoint.
	log.Infof("Creating HNS endpoint: %+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSEndpointRequest("POST", "", hnsRequest)
	if err != nil {
		log.Errorf("Failed to create HNS endpoint: %v.", err)
		return err
	}

	log.Infof("Received HNS endpoint response: %+v.", hnsResponse)

	// Attach the HNS endpoint to the container's network namespace.
	err = hns.AttachEndpoint(hnsResponse, nsType, ep.ContainerID, namespaceIdentifier)
	if err != nil {
		// Cleanup the failed endpoint.
		log.Infof("Deleting the failed HNS endpoint %s.", hnsResponse.Id)
		_, delErr := hcsshim.HNSEndpointRequest("DELETE", hnsResponse.Id, "")
		if delErr != nil {
			log.Errorf("Failed to delete HNS endpoint: %v.", delErr)
		}

		return err
	}

	// Return network interface MAC address.
	ep.MACAddress, _ = net.ParseMAC(hnsResponse.MacAddress)

	return nil
}

// DeleteEndpoint deletes an existing HNS endpoint.
func (nb *BridgeBuilder) DeleteEndpoint(nw *Network, ep *Endpoint) error {
	// Query the namespace identifier.
	nsType, namespaceIdentifier := hns.GetNamespaceIdentifier(ep.NetNSName, ep.ContainerID)

	// Find the HNS endpoint ID.
	endpointName := nb.generateHNSEndpointName(ep, namespaceIdentifier)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return err
	}

	// Detach the HNS endpoint from the container's network namespace.
	err = hns.DetachEndpoint(hnsEndpoint, nsType, ep.ContainerID, namespaceIdentifier)
	if err != nil {
		return err
	}

	// The rest of the delete logic applies to infrastructure container only.
	if nsType == hns.AppContainerNS {
		// For non-infra containers, the network must not be deleted.
		return nil
	}

	// Delete the HNS endpoint.
	log.Infof("Deleting HNS endpoint name: %s ID: %s", endpointName, hnsEndpoint.Id)
	_, err = hcsshim.HNSEndpointRequest("DELETE", hnsEndpoint.Id, "")
	if err != nil {
		log.Errorf("Failed to delete HNS endpoint: %v.", err)
	}

	return err
}

// addEndpointPolicy adds a policy to an HNS endpoint.
func (nb *BridgeBuilder) addEndpointPolicy(ep *hcsshim.HNSEndpoint, policy interface{}) error {
	buf, err := json.Marshal(policy)
	if err != nil {
		log.Errorf("Failed to encode policy: %v.", err)
		return err
	}

	ep.Policies = append(ep.Policies, buf)

	return nil
}

// checkHNSVersion returns whether the Windows Host Networking Service version is supported.
func (nb *BridgeBuilder) checkHNSVersion() error {
	hnsGlobals, err := hcsshim.GetHNSGlobals()
	if err != nil {
		return err
	}

	hnsVersion := hnsGlobals.Version
	log.Infof("Running on HNS version: %+v", hnsVersion)

	supported := hnsVersion.Major > hnsMinVersion.Major ||
		(hnsVersion.Major == hnsMinVersion.Major && hnsVersion.Minor >= hnsMinVersion.Minor)

	if !supported {
		return fmt.Errorf("HNS is older than the minimum supported version %v", hnsMinVersion)
	}

	return nil
}

// generateHNSNetworkName generates a deterministic unique name for an HNS network.
func (nb *BridgeBuilder) generateHNSNetworkName(nw *Network) string {
	// Use the MAC address of the shared ENI as the deterministic unique identifier.
	id := strings.Replace(nw.SharedENI.GetMACAddress().String(), ":", "", -1)
	return fmt.Sprintf(hnsNetworkNameFormat, nw.Name, id)
}

// generateHNSEndpointName generates a deterministic unique name for an HNS endpoint.
func (nb *BridgeBuilder) generateHNSEndpointName(ep *Endpoint, id string) string {
	// Use the given optional identifier or the container ID itself as the unique identifier.
	if id == "" {
		id = ep.ContainerID
	}

	return fmt.Sprintf(hnsEndpointNameFormat, id)
}
