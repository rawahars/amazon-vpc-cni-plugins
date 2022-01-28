package hns

import (
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	log "github.com/cihub/seelog"
)

// NSType identifies the namespace type for the containers.
type NSType int

const (
	// InfraContainerNS identifies an Infra container NS for networking setup.
	InfraContainerNS NSType = iota
	// AppContainerNS identifies sharing of infra container NS for networking setup.
	AppContainerNS
	// HcnNamespace identifies HCN NS for networking setup.
	HcnNamespace
)

// GetNamespaceIdentifier identifies the namespace type and returns the appropriate identifier.
func GetNamespaceIdentifier(netNSName string, containerID string) (NSType, string) {
	// Orchestrators like Kubernetes and ECS group a set of containers into deployment units called
	// pods or tasks. The orchestrator agent injects a special container called infrastructure
	// (a.k.a. pause) container into each group to create and share namespaces with the other
	// containers in the same group.
	//
	// Normally, the CNI plugin is called only once, for the infrastructure container. It does not
	// need to know about infrastructure containers and is not even aware of the other containers
	// in the group. However, on older versions of Kubernetes and Windows (pre-1809), CNI plugin is
	// called for each container in the pod separately so that the plugin can attach the endpoint
	// to each container. The logic below is necessary to detect infrastructure containers and
	// maintain compatibility with those older versions.

	const containerPrefix string = "container:"
	var netNSType NSType
	var namespaceIdentifier string

	if netNSName == "none" || netNSName == "" {
		// This is the first, i.e. infrastructure, container in the group.
		// The namespace identifier for such containers would be their container ID.
		netNSType = InfraContainerNS
		namespaceIdentifier = containerID
	} else if strings.HasPrefix(netNSName, containerPrefix) {
		// This is a workload container sharing the netns of a previously created infra container.
		// The namespace identifier for such containers would be the infra container's ID.
		netNSType = AppContainerNS
		namespaceIdentifier = strings.TrimPrefix(netNSName, containerPrefix)
		log.Infof("Container %s shares netns of container %s.", containerID, namespaceIdentifier)
	} else {
		// This plugin invocation does not need an infra container and uses an existing HCN Namespace.
		// The namespace identifier would be the HCN Namespace id.
		netNSType = HcnNamespace
		namespaceIdentifier = netNSName
		log.Infof("Container %s is in network namespace %s.", containerID, namespaceIdentifier)
	}

	return netNSType, namespaceIdentifier
}

// AttachEndpoint attaches an HNS endpoint to a container's network namespace.
func AttachEndpoint(ep *hcsshim.HNSEndpoint, nsType NSType, containerID string, netNSName string) error {
	if nsType == InfraContainerNS || nsType == AppContainerNS {
		return attachEndpointV1(ep, containerID)
	} else {
		return attachEndpointV2(ep, netNSName)
	}
}

// DetachEndpoint detaches an HNS endpoint from a container's network namespace.
func DetachEndpoint(ep *hcsshim.HNSEndpoint, nsType NSType, containerID string, netNSName string) error {
	log.Infof("Detaching HNS endpoint %s from container %s netns.", ep.Id, containerID)
	var err error
	if nsType == HcnNamespace {
		// Detach the HNS endpoint from the namespace, if we can.
		// HCN Namespace and HNS Endpoint have a 1-1 relationship, therefore,
		// even if detachment of endpoint from namespace fails, we can still proceed to delete it.
		err = hcn.RemoveNamespaceEndpoint(netNSName, ep.Id)
		if err != nil {
			log.Errorf("Failed to detach endpoint, ignoring: %v", err)
		}
	} else {
		err = hcsshim.HotDetachEndpoint(containerID, ep.Id)
		if err != nil && err != hcsshim.ErrComputeSystemDoesNotExist {
			return err
		}
	}

	return nil
}

// attachEndpointV1 attaches an HNS endpoint to a container's network namespace using HNS V1 APIs.
func attachEndpointV1(ep *hcsshim.HNSEndpoint, containerID string) error {
	log.Infof("Attaching HNS endpoint %s to container %s.", ep.Id, containerID)
	err := hcsshim.HotAttachEndpoint(containerID, ep.Id)
	if err != nil {
		// Attach can fail if the container is no longer running and/or its network namespace
		// has been cleaned up.
		log.Errorf("Failed to attach HNS endpoint %s: %v.", ep.Id, err)
	}

	return err
}

// attachEndpointV2 attaches an HNS endpoint to a network namespace using HNS V2 APIs.
func attachEndpointV2(ep *hcsshim.HNSEndpoint, netNSName string) error {
	log.Infof("Adding HNS endpoint %s to ns %s.", ep.Id, netNSName)

	// Check if endpoint is already in target namespace.
	nsEndpoints, err := hcn.GetNamespaceEndpointIds(netNSName)
	if err != nil {
		log.Errorf("Failed to get endpoints from namespace %s: %v.", netNSName, err)
		return err
	}
	for _, endpointID := range nsEndpoints {
		if ep.Id == endpointID {
			log.Infof("HNS endpoint %s is already in ns %s.", endpointID, netNSName)
			return nil
		}
	}

	// Add the endpoint to the target namespace.
	err = hcn.AddNamespaceEndpoint(netNSName, ep.Id)
	if err != nil {
		log.Errorf("Failed to attach HNS endpoint %s: %v.", ep.Id, err)
	}

	return err
}
