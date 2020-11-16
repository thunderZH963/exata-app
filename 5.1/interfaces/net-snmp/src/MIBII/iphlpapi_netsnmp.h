/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    iphlpapi.h

Abstract:
    Header file for functions to interact with the IP Stack for MIB-II and
    related functionality

--*/

#ifndef __IPHLPAPI_H__
#define __IPHLPAPI_H__

//////////////////////////////////////////////////////////////////////////////
//                                                                          //
// Gets the MIB-II IfTable                                                  //
//                                                                          //
//////////////////////////////////////////////////////////////////////////////

DWORD
WINAPI
GetIfTable(
    OUT    PMIB_IFTABLE pIfTable,
    IN OUT PULONG       pdwSize,
    IN     BOOL         bOrder);

#endif //__IPHLPAPI_H__
