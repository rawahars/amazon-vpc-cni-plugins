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

package plugin

import (
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-shared-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/current"
)

// Add is the CNI ADD command handler.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v ContainerID:%v Netns:%v IfName:%v Args:%v.",
		netConfig, args.ContainerID, args.Netns, args.IfName, args.Args)

	// If this container shares another container's network namespace, use that infrastructure
	// container's ID instead. Orchestrators like Kubernetes and ECS use this feature to group
	// a set of containers into a single deployment unit called pod (K8S) or task (ECS).
	if strings.HasPrefix(args.Netns, "container:") {
		cid := strings.TrimPrefix(args.Netns, "container:")
		log.Infof("ContainerID %s shares the netns of containerID %s", args.ContainerID, cid)
		args.ContainerID = cid
	}

	// Find the ENI.
	sharedENI, err := eni.NewENI(netConfig.ENIName, netConfig.ENIMACAddress)
	if err != nil {
		log.Errorf("Failed to find ENI %s: %v.", netConfig.ENIName, err)
		return err
	}

	// Find the ENI link.
	err = sharedENI.AttachToLink()
	if err != nil {
		log.Errorf("Failed to find ENI link: %v.", err)
		return err
	}

	// Call the operating system specific network builder.
	nb := plugin.nb

	// Find or create the container network for the shared ENI.
	nw := Network{
		Name:             netConfig.Name,
		BridgeNetNSName:  netConfig.BridgeNetNSName,
		SharedENI:        sharedENI,
		ENIIPAddress:     netConfig.ENIIPAddress,
		GatewayIPAddress: netConfig.GatewayIPAddress,
	}

	err = nb.FindOrCreateNetwork(&nw)
	if err != nil {
		log.Errorf("Failed to create network: %v.", err)
		return err
	}

	// Find or create the container endpoint on the network.
	ep := Endpoint{
		ContainerID: args.ContainerID,
		NetNSName:   args.Netns,
		IfName:      args.IfName,
		IPAddress:   netConfig.IPAddress,
	}

	err = nb.FindOrCreateEndpoint(&nw, &ep)
	if err != nil {
		log.Errorf("Failed to create endpoint: %v.", err)
		return err
	}

	// Generate CNI result.
	result := &cniTypesCurrent.Result{
		Interfaces: []*cniTypesCurrent.Interface{
			{
				Name:    args.IfName,
				Mac:     ep.MACAddress.String(),
				Sandbox: args.Netns,
			},
		},
		IPs: []*cniTypesCurrent.IPConfig{
			{
				Version:   "4",
				Interface: cniTypesCurrent.Int(0),
				Address:   *netConfig.IPAddress,
				Gateway:   netConfig.GatewayIPAddress,
			},
		},
	}

	// Output CNI result.
	log.Infof("Writing CNI result to stdout: %+v", result)
	err = cniTypes.PrintResult(result, netConfig.CNIVersion)
	if err != nil {
		log.Errorf("Failed to print result for CNI ADD command: %v", err)
	}

	return err
}

// Del is the CNI DEL command handler.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v ContainerID:%v Netns:%v IfName:%v Args:%v.",
		netConfig, args.ContainerID, args.Netns, args.IfName, args.Args)

	// Find the ENI.
	sharedENI, err := eni.NewENI(netConfig.ENIName, netConfig.ENIMACAddress)
	if err != nil {
		log.Errorf("Failed to find ENI %s: %v.", netConfig.ENIName, err)
		return err
	}

	// Find the ENI link.
	err = sharedENI.AttachToLink()
	if err != nil {
		log.Errorf("Failed to find ENI link: %v.", err)
		return err
	}

	// Call operating system specific handler.
	nb := plugin.nb

	nw := Network{
		Name:            netConfig.Name,
		BridgeNetNSName: netConfig.BridgeNetNSName,
		SharedENI:       sharedENI,
	}

	ep := Endpoint{
		ContainerID: args.ContainerID,
		NetNSName:   args.Netns,
		IfName:      args.IfName,
		IPAddress:   netConfig.IPAddress,
	}

	err = nb.DeleteEndpoint(&nw, &ep)
	if err != nil {
		// DEL is best-effort. Log and ignore the failure.
		log.Errorf("Failed to delete endpoint, ignoring: %v", err)
	}

	return nil
}
