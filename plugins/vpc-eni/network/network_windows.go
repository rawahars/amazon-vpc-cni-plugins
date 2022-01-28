// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package network

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/hns"
	"github.com/aws/amazon-vpc-cni-plugins/network/imds"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	"github.com/Microsoft/hcsshim"
	log "github.com/cihub/seelog"
)

const (
	// hnsNetworkNameFormat is the format of the HNS network name.
	hnsNetworkNameFormat = "%sbr%s"
	// hnsEndpointNameFormat is the format of the HNS Endpoint name.
	hnsEndpointNameFormat = "%s-ep-%s"
	// hnsTransparentNetworkType is the Type of the HNS Network created by the plugin.
	hnsTransparentNetworkType = "Transparent"
	// vNICNameFormat is the name format of vNIC created by Windows.
	vNICNameFormat = "vEthernet (%s)"
	// netshDisableInterface is the netsh command to disable a network interface.
	netshDisableInterface = "Disable-NetAdapter -Name \"%s\" -Confirm:$false"
)

var (
	// hnsMinVersion is the minimum version of HNS supported by this plugin.
	hnsMinVersion = hcsshim.HNSVersion1803
)

// NetBuilder implements the Builder interface by moving an eni into a container namespace for Windows.
type NetBuilder struct{}

// FindOrCreateNetwork creates a new HNS network.
func (nb *NetBuilder) FindOrCreateNetwork(nw *Network) error {
	// Check that the HNS version is supported.
	err := nb.checkHNSVersion()
	if err != nil {
		return err
	}

	nw.Name = nb.generateHNSNetworkName(nw)
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(nw.Name)
	if err == nil {
		log.Infof("Found existing HNS network %s.", nw.Name)
		return nil
	}

	// If existing network flag is enabled, many of the parameters of netConfig become optional.
	// This can potentially lead to failure in network creation.
	// Therefore, return error at this point.
	if nw.UseExisting {
		log.Errorf("Failed to find existing network: %s.", nw.Name)
		return fmt.Errorf("failed to find existing network %s", nw.Name)
	}

	// Find the ENI link.
	err = nw.ENI.AttachToLink()
	if err != nil {
		log.Errorf("Failed to find ENI link: %v.", err)
		return err
	}

	// Initialize the HNS network.
	hnsNetwork = &hcsshim.HNSNetwork{
		Name:               nw.Name,
		Type:               hnsTransparentNetworkType,
		NetworkAdapterName: nw.ENI.GetLinkName(),

		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix: vpc.GetSubnetPrefix(&nw.IPAddresses[0]).String(),
			},
		},
	}

	// Gateway IP addresses are optional, therefore, if they are available then add the first one.
	if len(nw.GatewayIPAddresses) != 0 {
		hnsNetwork.Subnets[0].GatewayAddress = nw.GatewayIPAddresses[0].String()
	}

	// Create the HNS network.
	log.Infof("Creating HNS network: %+v", hnsNetwork)
	hnsResponse, err := hnsNetwork.Create()
	if err != nil {
		log.Errorf("Failed to create HNS network: %v.", err)
		return err
	}

	log.Infof("Received HNS network response: %+v.", hnsResponse)

	// For the new network, disable the vNIC in the host compartment.
	mgmtIface := fmt.Sprintf(vNICNameFormat, nw.ENI.GetLinkName())
	err = nb.disableInterface(mgmtIface)
	if err != nil {
		// This is a fatal error as the management vNIC must be disabled.
		_ = nb.DeleteNetwork(nw)
		return err
	}

	return nil
}

// DeleteNetwork deletes an existing HNS network.
func (nb *NetBuilder) DeleteNetwork(nw *Network) error {
	// Find the HNS network.
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(nw.Name)
	if err != nil {
		return err
	}

	// Delete the HNS network.
	log.Infof("Deleting HNS network name: %s ID: %s", nw.Name, hnsNetwork.Id)
	_, err = hnsNetwork.Delete()
	if err != nil {
		log.Errorf("Failed to delete HNS network: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint creates a new HNS endpoint in the network.
func (nb *NetBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// Query the namespace identifier.
	nsType, namespaceIdentifier := hns.GetNamespaceIdentifier(ep.NetNSName, ep.ContainerID)

	// Check if the endpoint already exists.
	endpointName := nb.generateHNSEndpointName(nw.Name, namespaceIdentifier)
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
			// Attachment of endpoint to each container would occur only when using HNS V1 APIs.
			err = hns.AttachEndpoint(hnsEndpoint, nsType, ep.ContainerID, namespaceIdentifier)
		}

		ep.MACAddress, ep.IPAddresses, nw.GatewayIPAddresses =
			nb.parseEndpointFieldsFromResponse(hnsEndpoint)
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
		VirtualNetworkName: nw.Name,
		DNSSuffix:          strings.Join(nw.DNSSuffixSearchList, ","),
		DNSServerList:      strings.Join(nw.DNSServers, ","),
	}

	if ep.MACAddress != nil {
		hnsEndpoint.MacAddress = ep.MACAddress.String()
	}
	if len(ep.IPAddresses) != 0 {
		hnsEndpoint.IPAddress = ep.IPAddresses[0].IP
		pl, _ := ep.IPAddresses[0].Mask.Size()
		hnsEndpoint.PrefixLength = uint8(pl)
	}

	// Add ACL policies for blocking IMDS access through the endpoint.
	if ep.BlockIMDS {
		err = imds.BlockInstanceMetadataEndpoint(hnsEndpoint)
		if err != nil {
			log.Errorf("Failed to block instance metadata endpoint: %v.", err)
			return err
		}
	}

	// Create the HNS endpoint.
	log.Infof("Creating HNS endpoint: %+v", hnsEndpoint)
	hnsResponse, err := hnsEndpoint.Create()
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
		_, delErr := hnsResponse.Delete()
		if delErr != nil {
			log.Errorf("Failed to delete HNS endpoint: %v.", delErr)
		}

		return err
	}

	// Return network interface MAC address, IP Address and Gateway.
	ep.MACAddress, ep.IPAddresses, nw.GatewayIPAddresses =
		nb.parseEndpointFieldsFromResponse(hnsResponse)
	return nil
}

// DeleteEndpoint deletes an existing HNS endpoint.
func (nb *NetBuilder) DeleteEndpoint(nw *Network, ep *Endpoint) error {
	// Generate network name here as endpoint name is dependent upon network name.
	nw.Name = nb.generateHNSNetworkName(nw)
	// Query the namespace identifier.
	nsType, namespaceIdentifier := hns.GetNamespaceIdentifier(ep.NetNSName, ep.ContainerID)

	// Find the HNS endpoint ID.
	endpointName := nb.generateHNSEndpointName(nw.Name, namespaceIdentifier)
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
		nw.UseExisting = true
		return nil
	}

	// Delete the HNS endpoint.
	log.Infof("Deleting HNS endpoint name: %s ID: %s", endpointName, hnsEndpoint.Id)
	_, err = hnsEndpoint.Delete()
	if err != nil {
		log.Errorf("Failed to delete HNS endpoint: %v.", err)
	}

	return err
}

// checkHNSVersion returns whether the Windows Host Networking Service version is supported.
func (nb *NetBuilder) checkHNSVersion() error {
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
func (nb *NetBuilder) generateHNSNetworkName(nw *Network) string {
	if nw.UseExisting {
		return nw.Name
	}

	// Unique identifier for the network would be of format "task-br-<eni mac address>".
	id := strings.Replace(nw.ENI.GetMACAddress().String(), ":", "", -1)
	return fmt.Sprintf(hnsNetworkNameFormat, nw.Name, id)
}

// generateHNSEndpointName generates a deterministic unique name for the HNS Endpoint.
func (nb *NetBuilder) generateHNSEndpointName(networkName string, identifier string) string {
	return fmt.Sprintf(hnsEndpointNameFormat, networkName, identifier)
}

// disableInterface disables the network interface with the provided name.
func (nb *NetBuilder) disableInterface(adapterName string) error {
	// Check if the interface exists.
	iface, err := net.InterfaceByName(adapterName)
	if err != nil {
		return err
	}

	// Check if the interface is enabled.
	isInterfaceEnabled := strings.EqualFold(strings.Split(iface.Flags.String(), "|")[0], "up")
	if isInterfaceEnabled {
		// Disable the interface using netsh.
		log.Infof("Disabling management vNIC %s in the host namespace.", adapterName)
		commandString := fmt.Sprintf(netshDisableInterface, adapterName)
		cmd := exec.Command("powershell", "-C", commandString)

		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// parseEndpointFieldsFromResponse parses and returns the MAC address, IP Address and Gateway address from HNS Endpoint response.
func (nb *NetBuilder) parseEndpointFieldsFromResponse(
	hnsResponse *hcsshim.HNSEndpoint) (net.HardwareAddr, []net.IPNet, []net.IP) {
	mac, _ := net.ParseMAC(hnsResponse.MacAddress)
	ipAddresses := []net.IPNet{
		{
			IP:   hnsResponse.IPAddress,
			Mask: net.CIDRMask(int(hnsResponse.PrefixLength), 32),
		},
	}
	gatewayAddresses := []net.IP{net.ParseIP(hnsResponse.GatewayAddress)}

	return mac, ipAddresses, gatewayAddresses
}
