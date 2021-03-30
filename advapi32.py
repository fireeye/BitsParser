# Copyright 2021 FireEye, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on 
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the 
# specific language governing permissions and limitations under the License.

import ctypes
from ctypes import wintypes

advapi32 = ctypes.windll.advapi32

_In_ = 1  # Specifies an input parameter to the function.
_Out_ = 2  # Output parameter. The foreign function fills in a value.


PSID = ctypes.POINTER(wintypes.BYTE)
UNLEN = 256


def errcheckBOOL(result, func, args):
    """Callback for APIs that return type BOOL."""
    if result == 0:
        raise ctypes.WinError()
    return args


def ConvertStringSidToSid(strsid):
    prototype = ctypes.WINFUNCTYPE(
        wintypes.BOOL,  # return type
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.PBYTE),
    )

    paramflags = (
        (_In_, 'StringSid'),
        (_Out_, 'Sid')
    )

    _ConvertStringSidToSid_ = prototype(('ConvertStringSidToSidW', advapi32), paramflags)
    _ConvertStringSidToSid_.errcheck = errcheckBOOL
    return _ConvertStringSidToSid_(strsid)


def LookupAccountSid(sid, machine=None):
    prototype = ctypes.WINFUNCTYPE(
        wintypes.BOOL,  # return value
        wintypes.LPCWSTR,
        PSID,
        wintypes.LPCWSTR,
        wintypes.LPDWORD,
        wintypes.LPCWSTR,
        wintypes.LPDWORD,
        wintypes.LPDWORD
    )
    paramflags = (
        (_In_, 'lpSystemName'),
        (_In_, 'lpSid'),
        (_Out_, 'lpName', ctypes.create_unicode_buffer(UNLEN)),
        (_In_, 'cchName', ctypes.byref(wintypes.DWORD(UNLEN))),
        (_Out_, 'lpReferencedDomainName', ctypes.create_unicode_buffer(UNLEN)),
        (_In_, 'cchReferencedDomainName', ctypes.byref(wintypes.DWORD(UNLEN))),
        (_Out_, 'peUse')
    )
    _LookupAccountSid = prototype(('LookupAccountSidW', advapi32), paramflags)
    _LookupAccountSid.errcheck = errcheckBOOL
    lpname, lprefdn, peuse = _LookupAccountSid(machine, sid)
    return (lpname.value, lprefdn.value, peuse)
