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

package endpoint

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/Microsoft/hcsshim"
)

type Endpoint interface {
	AddRoute(DestinationPrefix string, NextHop string) error
	DeleteRoute(DestinationPrefix string, NextHop string) error
}

// endpoint represents an hns endpoint on Windows.
type endpoint struct {
	Name          string
	CompartmentID uint32
}

// New returns a new instance of Endpoint.
func New(Name string, CompartmentID uint32) Endpoint {
	return &endpoint{
		Name:          Name,
		CompartmentID: CompartmentID,
	}
}

// AddRoute adds a route for the given interface in it's network namespace.
func (ep *endpoint) AddRoute(DestinationPrefix string, NextHop string) error {
	mibRow, err := ep.createMibIPForwardRow(DestinationPrefix, NextHop)
	if err != nil {
		return fmt.Errorf("failed to create MIB_IPFORWARD_ROW2 struct: %w", err)
	}

	// Add route inside container compartment if not present.
	var funcErr error
	err = executeInCompartment(ep.CompartmentID, func() {
		funcErr = mibRow.get()
		if funcErr == nil {
			// Route already present, return.
			funcErr = fmt.Errorf("route already found inside container namespace: destination: %s and next hop: %s",
				DestinationPrefix, NextHop)
			return
		}
		// Route not present and therefore create the same.
		funcErr = mibRow.create()
	})
	if err != nil || funcErr != nil {
		if err != nil {
			return fmt.Errorf("failed to execute create route method inside container namespace: %w", err)
		}
		if funcErr != nil {
			return fmt.Errorf("failed to create route inside container namespace: %w", funcErr)
		}
	}

	return nil
}

// DeleteRoute deletes a route for the given interface in it's network namespace.
func (ep *endpoint) DeleteRoute(DestinationPrefix string, NextHop string) error {
	mibRow, err := ep.createMibIPForwardRow(DestinationPrefix, NextHop)
	if err != nil {
		return fmt.Errorf("failed to create MIB_IPFORWARD_ROW2 struct: %w", err)
	}

	// delete route inside container compartment if present.
	var funcErr error
	err = executeInCompartment(ep.CompartmentID, func() {
		funcErr = mibRow.get()
		if funcErr != nil {
			// Route not found in container namespace and therefore, return.
			return
		}

		// Route was found inside container namespace and therefore delete it.
		funcErr = mibRow.delete()
	})
	if err != nil || funcErr != nil {
		if err != nil {
			return fmt.Errorf("failed to execute delete route method inside container namespace: %w", err)
		}
		if funcErr != nil {
			return fmt.Errorf("failed to delete route inside container namespace: %w", funcErr)
		}
	}

	return nil

}

func (ep *endpoint) getInterfaceIndex() (uint32, error) {
	iface, err := net.InterfaceByName(ep.Name)
	if err != nil {
		return 0, fmt.Errorf("failed to find interface with name %s: %w", iface.Name, err)
	}

	return uint32(iface.Index), nil
}

func (ep *endpoint) createMibIPForwardRow(DestinationPrefix string, NextHop string) (mibIPforwardRow2, error) {
	prefix, err := netip.ParsePrefix(DestinationPrefix)
	if err != nil {
		return mibIPforwardRow2{}, fmt.Errorf("failed to parse prefix: %w", err)
	}

	hop, err := netip.ParseAddr(NextHop)
	if err != nil {
		return mibIPforwardRow2{}, fmt.Errorf("failed to parse address: %w", err)
	}

	destinationPrefix := iPAddressPrefix{}
	err = destinationPrefix.setPrefix(prefix)
	if err != nil {
		return mibIPforwardRow2{}, fmt.Errorf("failed to parse ip address prefix: %w", err)
	}

	nextHop := rawSockaddrInet{}
	err = nextHop.setAddr(hop)
	if err != nil {
		return mibIPforwardRow2{}, fmt.Errorf("failed to parse address: %w", err)
	}

	// Find interface index.
	var ifIndex uint32
	var funcErr error
	err = executeInCompartment(ep.CompartmentID, func() {
		ifIndex, funcErr = ep.getInterfaceIndex()
	})
	if err != nil || funcErr != nil {
		if err != nil {
			return mibIPforwardRow2{}, fmt.Errorf("failed to execute getInterfaceIndex method inside container namespace: %w", err)
		}
		if funcErr != nil {
			return mibIPforwardRow2{}, fmt.Errorf("failed to find interface index inside container namespace: %w", funcErr)
		}
	}

	return mibIPforwardRow2{
		destinationPrefix: destinationPrefix,
		nextHop:           nextHop,
		interfaceIndex:    ifIndex,
	}, nil
}

// executeInCompartment executes a method in the specified compartment.
// This method has been taken from the moby implementation.
// Reference: https://github.com/moby/moby/blob/e8a79114b8c1782d5539421c9a6a1cd6fc5dfa65/libnetwork/network_windows.go#L17
func executeInCompartment(compartmentID uint32, x func()) error {
	// Lock the OS thread in which the current Goroutine is running.
	runtime.LockOSThread()

	// Set the compartment ID where we need to execute the method.
	if err := hcsshim.SetCurrentThreadCompartmentId(compartmentID); err != nil {
		return fmt.Errorf("error while setting thread compartment: %w", err)
	}

	// Before returning, we need to set the compartment back to the host.
	defer func() {
		err := hcsshim.SetCurrentThreadCompartmentId(0)
		if err != nil {
			panic("failed to reset the thread compartment to host")
		}
		runtime.UnlockOSThread()
	}()

	// Execute the method.
	x()

	return nil
}
