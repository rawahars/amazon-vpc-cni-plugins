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
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var (
	// moduleIPHelper is the IP Helper module.
	// https://learn.microsoft.com/en-us/windows/win32/iphlp/about-ip-helper
	moduleIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")

	// procGetIpForwardEntry2 is the GetIpForwardEntry2 Win32 API procedure.
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2
	procGetIpForwardEntry2 = moduleIPHelper.NewProc("GetIpForwardEntry2")
	// procCreateIpForwardEntry2 is the CreateIpForwardEntry2 Win32 API procedure.
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2
	procCreateIpForwardEntry2 = moduleIPHelper.NewProc("CreateIpForwardEntry2")
	// procDeleteIpForwardEntry2 is the DeleteIpForwardEntry2 Win32 API procedure.
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2
	procDeleteIpForwardEntry2 = moduleIPHelper.NewProc("DeleteIpForwardEntry2")
)

// rawSockaddrInet represents the SOCKADDR_INET union struct.
// https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_inet
type rawSockaddrInet struct {
	family uint16
	data   [26]byte
}

// setAddr can be used to set the address in rawSockaddrInet.
func (addr *rawSockaddrInet) setAddr(netAddr netip.Addr) error {
	if netAddr.Is4() {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		addr4.Family = windows.AF_INET
		addr4.Addr = netAddr.As4()
		addr4.Port = 0
		return nil
	} else if netAddr.Is6() {
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		addr6.Family = windows.AF_INET6
		addr6.Addr = netAddr.As16()
		addr6.Port = 0
		addr6.Flowinfo = 0
		scopeId := uint32(0)
		if z := netAddr.Zone(); z != "" {
			if s, err := strconv.ParseUint(z, 10, 32); err == nil {
				scopeId = uint32(s)
			}
		}
		addr6.Scope_id = scopeId
		return nil
	}
	return windows.ERROR_INVALID_PARAMETER
}

// iPAddressPrefix structure stores an IP address prefix.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-ip_address_prefix
type iPAddressPrefix struct {
	rawPrefix    rawSockaddrInet
	prefixLength uint8
	_            [2]byte
}

// setPrefix can be used to set the value of iPAddressPrefix.
func (prefix *iPAddressPrefix) setPrefix(netPrefix netip.Prefix) error {
	err := prefix.rawPrefix.setAddr(netPrefix.Addr())
	if err != nil {
		return err
	}
	prefix.prefixLength = uint8(netPrefix.Bits())
	return nil
}

// mibIPforwardRow2 structure stores information about an IP route entry.
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
type mibIPforwardRow2 struct {
	interfaceLUID        uint64
	interfaceIndex       uint32
	destinationPrefix    iPAddressPrefix
	nextHop              rawSockaddrInet
	sitePrefixLength     uint8
	validLifetime        uint32
	preferredLifetime    uint32
	metric               uint32
	protocol             uint32
	loopback             bool
	autoconfigureAddress bool
	publish              bool
	immortal             bool
	age                  uint32
	origin               uint32
}

// get invokes the GetIpForwardEntry2 Win32 function to retrieve the route entry.
func (row *mibIPforwardRow2) get() error {
	retVal, _, _ := procGetIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if retVal != 0 {
		return errors.Errorf("error occured while calling GetIpForwardEntry2: %s", syscall.Errno(retVal))
	}

	return nil
}

// create invokes the CreateIpForwardEntry2 Win32 function to create the route entry.
func (row *mibIPforwardRow2) create() error {
	retVal, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if retVal != 0 {
		return errors.Errorf("error occured while calling CreateIpForwardEntry2: %s", syscall.Errno(retVal))
	}

	return nil
}

// delete invokes the DeleteIpForwardEntry2 Win32 function to delete the route entry.
func (row *mibIPforwardRow2) delete() error {
	retVal, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if retVal != 0 {
		return errors.Errorf("error occured while calling DeleteIpForwardEntry2: %s", syscall.Errno(retVal))
	}

	return nil
}
