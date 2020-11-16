// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

// /**
// PROTOCOL :: ATM_IP SAAL (signaling ATM adaptation layer)
//
// SUMMARY  :: As the name suggest the main goal of ATM-IP interaction
// is to transfer IP traffic over the ATM network to reach the final
// destination. In this regard, Classical IP over ATM model is
// introduced with the concept of a logical entity called
// LOGICAL IP SUBNET that treats the ATM network as a number of
// separate IP subnets connected through routers. The membership to
// an LIS is defined by software configuration. Transportation of
// various protocol data unit over an ATM network are categorized
// into the following subsection
//    Addressing
//    Address resolution
//    Data encapsulation
//    Routing

//
// LAYER :: ADAPTATION.
//
// STATISTICS::
// + numOfAtmSetupSent: Total number of setup sent
// + numOfAtmSetupRecv: Total number of setup recv
// + numOfAtmCallProcSent: Total number of call proceding sent
// + numOfAtmCallProcRecv: Total number of call proceding recv
// + numOfAtmConnectSent: Total number of Connect packet sent
// + numOfAtmConnectRecv: Total number of Connect packet recv
// + numOfAtmConnectAckSent: Total number of Connect ack sent
// + numOfAtmConnectAckRecv: Total number of Connect ack recv
// + numOfAtmAlertSent: Total number of Alert sent
// + numOfAtmAlertRecv: Total number of Alert recv
// + numOfAtmReleaseSent: Total number of release sent
// + numOfAtmReleaseRecv: Total number of release recv
// + numOfAtmReleaseCompleteSent: Total number of rel compl sent
// + numOfAtmReleaseCompleteRecv: Total number of rel compl recv

//
// CONFIG_PARAM ::
// + conncTimeoutTime : TIME : SVC connection refresh Time
// + conncRefreshTime : TIME : Virtual connection timeout time

//
// VALIDATION :: $QUALNET_HOME/verification/atm-ip.
//
// IMPLEMENTED_FEATURES ::
// + PACKET TYPE : Only Signaling and Unicast data payload are implemented.
// + NETWORK TYPE : Point to point ATM link are supported.
// + LINK TYPE : Wired.
// + FUNCTIONALITY : IP Protocol Data Units are carried over the ATM cloud
//                   through the Gateways.
//                 : Logical Subnet concept is introduced. At present,
//                   single Logical IP subnet is supported within ATM cloud,
//                 : Routing within the ATM clouds is done statically. Static
//                   route file is provided externally during configuration.
//                 : Virtual path setup process for each application is done
//                   dynamically, Various signaling messages are exchanged
//                   for setup virtual paths.
//                 : BW are reserved for each application.

//
// OMITTED_FEATURES ::
// +PACKET TYPE : Broadcast and multicast packets are not implemented.
// +ROUTE TYPE : Only static route within ATM cloud is implemented.
// + PNNI Routing is not implemented within ATM.
// + PVC is not implemented.

// ASSUMPTIONS ::
// + ATM is working as a backbone cloud to transfer the traffic i.e. all the
// IP clouds are connected to backbone ATM cloud & have a DEFAULT-GATEWAY,
//.acting as an entry/exit point to/from the ATM cloud.
// + all application requires a fixed BW, described as SAAL_DEFAULT_BW
// parameter.
// + All nodes in a single ATM cloud are part of the same Logical Subnet.
// + Every ATM end-system should have at least one interface connected to IP.

#ifndef SAAL_H
#define SAAL_H

#include "api.h"
#include "partition.h"
#include "mac_link.h"
#include "network_ip.h"
#include "list.h"


// /**
// CONSTANT    :: SAAL_INVALID_VPI : 255
// DESCRIPTION :: Invalid VPI for SAAL is 255.
// **/
#define SAAL_INVALID_VPI 255


// /**
// CONSTANT    :: SAAL_BUSY_PATH : 1
// DESCRIPTION :: Busy path value for SAAL
// **/
#define SAAL_BUSY_PATH 1


// /**
// CONSTANT    :: SAAL_IDLE_PATH : 0
// DESCRIPTION :: Idle path value for SAAL
// **/
#define SAAL_IDLE_PATH 0


// /**
// CONSTANT    :: SAAL_DEFAULT_BW : 500
// DESCRIPTION :: It is assumed that each application requires 0.5 Mbps
//                of BandWidth
// **/
#define SAAL_DEFAULT_BW 500 // in bps


// /**
// CONSTANT    :: SAAL_TIMER_T301_DELAY : (3 * MINUTE)
// DESCRIPTION :: Various timer used for controlling signalling
//                behaviour in ATM.
// **/
#define SAAL_TIMER_T301_DELAY  (3 * MINUTE)  //Minimum3 min


// /**
// CONSTANT    :: SAAL_TIMER_T303_DELAY : (4 * SECOND)
// DESCRIPTION :: T303 delay for SAAL timer.
// **/
#define SAAL_TIMER_T303_DELAY  (4 * SECOND)


// /**
// CONSTANT    :: SAAL_TIMER_T306_DELAY : (30 * SECOND)
// DESCRIPTION :: T306 delay for SAAL timer.
// **/
#define SAAL_TIMER_T306_DELAY  (30 * SECOND)


// /**
// CONSTANT    :: SAAL_TIMER_T310_DELAY : (10 * SECOND)
// DESCRIPTION :: T310 delay for SAAL timer.
// **/
#define SAAL_TIMER_T310_DELAY  (10 * SECOND)


// /**
// CONSTANT    :: SAAL_TIMER_T313_DELAY : (4 * SECOND)
// DESCRIPTION :: T313 delay for SAAL timer.
// **/
#define SAAL_TIMER_T313_DELAY  (4 * SECOND)


// /**
// CONSTANT    :: SAAL_CONNECT_TIMER_DELAY : (1 * SECOND)
// DESCRIPTION ::
// **/
#define SAAL_CONNECT_TIMER_DELAY (1 * SECOND)


// /**
// CONSTANT    :: RROTOCOL_DISCLAIMER : 9
// DESCRIPTION ::
// **/
#define RROTOCOL_DISCLAIMER  9


// /**
// CONSTANT    :: MAX_SEQ_NUMBER : 250
// DESCRIPTION :: Maxium sequence number.
// **/
#define MAX_SEQ_NUMBER 250


// /**
// CONSTANT    :: SAAL_INVALID_INTERFACE : -1
// DESCRIPTION :: Invalid SAAL interface.
// **/
#define SAAL_INVALID_INTERFACE  -1


// /**
// ENUM        :: SaalSignalingStatus
// DESCRIPTION :: Various signalling status for SAAL
// **/
typedef enum
{
    SAAL_INVALID_STATUS,
        SAAL_NOT_YET_STARTED,
        SAAL_IN_PROGRESS,
        SAAL_COMPLETED,
        SAAL_TERMINATED
} SaalSignalingStatus;


// /**
// ENUM        :: SaalMsgType
// DESCRIPTION :: Various message type for SAAL
// **/
typedef enum
{
    SAAL_SETUP                      = 5,
        SAAL_CALL_PROCEEDING            = 2,
        SAAL_CONNECT                    = 7 ,
        SAAL_CONNECT_ACK                = 15,
        SAAL_ALERT                      = 1,
        SAAL_PROGRESS                   = 3,
        SAAL_SETUP_ACKNOWLEDGE          = 13,
        SAAL_RELEASE                    = 77,
        SAAL_RELEASE_COMPLETE           = 90
} SaalMsgType;


// /**
// ENUM        :: SaalCallState
// DESCRIPTION :: Various call states for SAAL
// **/
typedef enum
{
    SAAL_NULL                      = 0,
        SAAL_CALL_INITIATED            = 1,
        SAAL_OUTGOING_CALL_PROCEEDING  = 3,
        SAAL_CALL_DELIVERED            = 4,
        SAAL_CALL_PRESENT              = 6,
        SAAL_CALL_RECEIVED             = 7,
        SAAL_CONNECT_REQUEST           = 8,
        SAAL_INCOMING_CALL_PROCEEDING  = 9,
        SAAL_ACTIVE                    = 10,
        SAAL_RELEASE_REQUEST           = 11,
        SAAL_RELEASE_INDICATION        = 12
} SaalCallState;


// /**
// ENUM        :: SaalCallEndPointType
// DESCRIPTION :: Various call endpoints foe SAAL
// **/
typedef enum
{
    CALLING_USER,
        CALLING_NET_SWITCH,
        CALLED_USER,
        CALLED_NET_SWITCH,
        COMMON_NET_SWITCH,
        NORMAL_POINT
} SaalCallEndPointType;


// /**
// ENUM        :: SaalTimerType
// DESCRIPTION :: Various Information element
// **/
typedef enum
{
    SAAL_TIMER_T301,
    SAAL_TIMER_T303,
    SAAL_TIMER_T306,
    SAAL_TIMER_T310,
    SAAL_TIMER_T313,
    SAAL_TIMER_CONNECT
} SaalTimerType;


// /**
// ENUM        :: SaalIEId
// DESCRIPTION :: Information element identifire for SAAL
// **/
typedef enum
{
    SAAL_IE_CALL_STATE_INFO            = 20 ,
    SAAL_IE_END_TO_END_DELAY           = 66,
    SAAL_IE_AALPARAM                   = 88 ,
    SAAL_IE_ATM_TR_DESC                = 89,
    SAAL_IE_CONNC_ID                   = 90 ,
    SAAL_IE_QOS_PARAM                  = 92,
    SAAL_IE_BROAD_HLAYER_INFO          = 93,
    SAAL_IE_BROAD_BR_CAP               = 94,
    SAAL_IE_BROAD_LLAYER_INFO          = 95,
    SAAL_IE_CALLING_PARTY_NUM          = 108,
    SAAL_IE_CALLING_PARTY_SUBADDRESS   = 109,
    SAAL_IE_CALLED_PARTY_NUM           = 112,
    SAAL_IE_CALLED_PARTY_SUBADDRESS     = 113
} SaalIEId;


//----------------------------------------------------------
//             Various IE related structure
//----------------------------------------------------------


// /**
// STRUCT      :: SaalInformationElement
// DESCRIPTION :: Information element header
// **/
typedef struct struct_saal_information_element
{
    unsigned char IE_identifier;
    unsigned char saalIele;//ext:1, codeStd:2, flag:1, res:1, actionInd:3;
    unsigned short IE_contentLn;
} SaalInformationElement;


// /**
// FUNCTION    :: SaalInfoElementSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// + ext        : Input value for set operation
// RETURN       : void : None
// **/
static void SaalInfoElementSetExt(unsigned char *saalIele, BOOL ext)
{
    unsigned char ext_char = (unsigned char)ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears the first bit
    *saalIele = *saalIele & maskChar(2, 8);

    //setting the value of ext in saalIele
    *saalIele = *saalIele | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalInfoElementSetCodeStd()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of codeStd for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// + codeStd    : Input value for set operation
// RETURN       : void : None
// **/
static void SaalInfoElementSetCodeStd(unsigned char *saalIele,
                                      unsigned char codeStd)
{
    //masks codeStd within boundry range
    codeStd = codeStd & maskChar(7, 8);

    //clears the second and third bit
    *saalIele = *saalIele & (~(maskChar(2, 3)));

    //setting the value of codeStd in saalIele
    *saalIele = *saalIele | LshiftChar(codeStd, 3);
}


// /**
// FUNCTION    :: SaalInfoElementSetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of flag for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// + flag       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalInfoElementSetFlag(unsigned char *saalIele, BOOL flag)
{
    unsigned char flag_char = (unsigned char)flag;

    //masks flag within boundry range
    flag_char = flag_char & maskChar(8, 8);

    //clears the fourth bit
    *saalIele = *saalIele & (~(maskChar(4, 4)));

    //setting the value of flag in saalIele
    *saalIele = *saalIele | LshiftChar(flag_char, 4);
}


// /**
// FUNCTION    :: SaalInfoElementSetRes()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of res forSaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// + res        : Input value for set operation
// RETURN       : void : None
// **/
static void SaalInfoElementSetRes(unsigned char *saalIele, BOOL res)
{
    unsigned char res_char = (unsigned char)res;

    //masks res within boundry range
    res_char = res_char & maskChar(8, 8);

    //clears the fifth bit
    *saalIele = *saalIele & (~(maskChar(5, 5)));

    //setting the value of preferred in saalIele
    *saalIele = *saalIele | LshiftChar(res_char, 5);
}


// /**
// FUNCTION    :: SaalInfoElementSetActionInd()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of actionInd forSaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// + actionInd  : Input value for set operation
// RETURN       : void : None
// **/
static void SaalInfoElementSetActionInd(unsigned char *saalIele,
                                        unsigned char actionInd)
{
    //masks actionInd within boundry range
    actionInd = actionInd & maskChar(6, 8);

    //clears the 6-8 bit
    *saalIele = *saalIele & maskChar(1, 5);

    //setting the value of actionInd in saalIele
    *saalIele = *saalIele | actionInd;
}


// /**
// FUNCTION    :: SaalInfoElementGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// RETURN       : BOOL
// **/
static BOOL SaalInfoElementGetExt(unsigned char saalIele)
{
    unsigned char ext = saalIele;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts so that last bit represents ext
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalInfoElementGetCodeStd()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of codeStd for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// RETURN       : UInt8
// **/
static UInt8 SaalInfoElementGetCodeStd(unsigned char saalIele)
{
    UInt8 codeStd = saalIele;

    //clears all the bits except second and third
    codeStd = codeStd & maskChar(2, 3);

    //right shifts so that last 2 bits represent codeStd
    codeStd = RshiftChar(codeStd, 3);

    return codeStd;
}


// /**
// FUNCTION    :: SaalInfoElementGetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of flag for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// RETURN       : BOOL
// **/
static BOOL SaalInfoElementGetFlag(unsigned char saalIele)
{
    UInt8 flag = (unsigned char)saalIele;

    //clears all the bits except fourth
    flag = flag & maskChar(4, 4);

    //right shifts so that last bit represents flag
    flag = RshiftChar(flag, 4);

    return (BOOL)flag;
}


// /**
// FUNCTION    :: SaalInfoElementGetRes()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of res for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// RETURN       : BOOL
// **/
static BOOL SaalInfoElementGetRes(unsigned char saalIele)
{
    UInt8 res = (unsigned char)saalIele;

    //clears all the bits except fifth
    res = res & maskChar(5, 5);

    //right shifts so that last bit represents res
    res = RshiftChar(res, 5);

    return (BOOL)res;
}


// /**
// FUNCTION    :: SaalInfoElementGetActionInd()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of actionInd for SaalInformationElement
// PARAMETERS  ::
// + saalIele   : The variable containing the value of ext,codeStd,flag,res
//                and actionInd
// RETURN       : UInt8
// **/
static UInt8 SaalInfoElementGetActionInd(unsigned char saalIele)
{
    UInt8 actionInd = saalIele;

    //clears all the bits except 6-8
    actionInd = actionInd & maskChar(6, 8);

    return actionInd;
}


// /**
// STRUCT      :: SaalIEAALParameters
// DESCRIPTION :: Information element AAL Parameters
// **/
typedef struct struct_saalieaalparameters
{
    SaalInformationElement ieField;
    unsigned char AALType;
    unsigned char subtypeId;
    unsigned char cbrRateId;
    unsigned char cbrRate;
    unsigned char fwdMaxCPCSSDUSizeId;
    unsigned short fwdMaxCPCSSDUSize;
    unsigned char bkdMaxCPCSSDUSizeId;
    unsigned short bkdMaxCPCSSDUSize;
    unsigned char SSCSTypeId;
    unsigned char SSCSType;
} SaalIEAALParameters;


// /**
// STRUCT      :: SaalIEATMTrDescriptor
// DESCRIPTION :: Information element ATM Traffic Descriptor.
// **/
typedef struct struct_saal_ie_Atm_tr_descriptor
{
    SaalInformationElement ieField;
    unsigned char fwdPeakCellRateId;
    unsigned short fwdPeakCellRate;
    unsigned char bkdPeakCellRateId;
    unsigned short bkdPeakCellRate;
} SaalIEATMTrDescriptor;


// /**
// STRUCT      :: SaalIEBrBearerCapability
// DESCRIPTION :: Information element Broadband bearer Capability
// **/
typedef struct struct_saal_iebr_bearer_capability
{
    SaalInformationElement ieField;
    unsigned char sIeBCap;//ext1:1, spare1:2, bearerCl:5;
    unsigned char sIeBearerCap;//ext2:1, spare2:2, TrType:3, TimeRq:2;
    unsigned char reserved;
} SaalIEBrBearerCapability;


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetExt1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext1 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBCap    : The variable containing the value of ext1,spare1 and
//                bearerC1
// + ext1       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetExt1(unsigned char *sIeBCap,
                                            BOOL ext1)
{
    unsigned char ext1_char = (unsigned char) ext1;

    //masks ext1 within boundry range
    ext1_char = ext1_char & maskChar(8, 8);

    //clears first bit
    *sIeBCap = *sIeBCap & maskChar(2, 8);

    //setting the value of ext1 in sIeBCap
    *sIeBCap = *sIeBCap | LshiftChar(ext1_char, 1);
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetSpare1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of spare1 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBCap    : The variable containing the value of ext1,spare1 and
//                bearerC1
// + spare1     : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetSpare1(unsigned char *sIeBCap,
                                              unsigned char spare1)
{
    //masks spare1 within boundry range
    spare1 = spare1 & maskChar(7, 8);

    //clears 2-3 bits
    *sIeBCap = *sIeBCap & (~(maskChar(2, 3)));

    //setting the value of spare1 in sIeBCap
    *sIeBCap = *sIeBCap | LshiftChar(spare1, 3);
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetBearerC1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of bearerC1 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBCap    : The variable containing the value of ext1,spare1 and
//                bearerC1
// + bearerC1   : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetBearerC1(unsigned char *sIeBCap,
                                                unsigned char bearerC1)
{
    //masks bearerC1 within boundry range
    bearerC1 = bearerC1 & maskChar(4, 8);

    //clears last 5 bits
    *sIeBCap = *sIeBCap & maskChar(1, 3);

    //setting the value of bearerC1 in sIeBCap
    *sIeBCap = *sIeBCap | bearerC1;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetExt2()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext2 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// + ext2         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetExt2(unsigned char *sIeBearerCap,
                                            BOOL ext2)
{
    unsigned char ext2_char = (unsigned char) ext2;

    //masks ext2 within boundry range
    ext2_char = ext2_char & maskChar(8, 8);

    //clears first bit
    *sIeBearerCap = *sIeBearerCap & maskChar(2, 8);

    //setting the value of ext2 in sIeBearerCap
    *sIeBearerCap = *sIeBearerCap | LshiftChar(ext2_char, 1);
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetSpare2()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of spare2 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// + spare2       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetSpare2(unsigned char *sIeBearerCap,
                                              unsigned char spare2)
{
    //masks spare2 within boundry range
    spare2 = spare2 & maskChar(7, 8);

    //clears 2-3 bits
    *sIeBearerCap = *sIeBearerCap & (~(maskChar(2, 3)));

    //setting the value of spare1 in sIeBCap
    *sIeBearerCap = *sIeBearerCap | LshiftChar(spare2, 3);
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetTrType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of TrType for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// + TrType       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetTrType(unsigned char *sIeBearerCap,
                                              unsigned char TrType)
{
    //masks TrType within boundry range
    TrType = TrType & maskChar(6, 8);

    //clears 4-6 bits
    *sIeBearerCap = *sIeBearerCap & (~(maskChar(4, 6)));

    //setting the value of TrType in sIeBearerCap
    *sIeBearerCap = *sIeBearerCap | LshiftChar(TrType, 6);
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilitySetTimeRq()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of TimeRq for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// + TimeRq       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrBearerCapabilitySetTimeRq(unsigned char *sIeBearerCap,
                                              unsigned char TimeRq)
{
    //masks TimeRq within boundry range
    TimeRq = TimeRq & maskChar(7, 8);

    //clears 4-6 bits
    *sIeBearerCap = *sIeBearerCap & maskChar(1, 6);

    //setting the value of TimeRq in sIeBearerCap
    *sIeBearerCap = *sIeBearerCap | TimeRq;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetExt1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext1 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBCap    : The variable containing the value of ext1,spare1 and
//                bearerC1
// RETURN       : BOOL
// **/
static BOOL SaalIEBrBearerCapabilityGetExt1(unsigned char sIeBCap)
{
    unsigned char ext = sIeBCap;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetSpare1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of spare1 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBCap    : The variable containing the value of ext1,spare1 and
//                bearerC1
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrBearerCapabilityGetSpare1(unsigned char sIeBCap)
{
    UInt8 spare = sIeBCap;

    //clears last 7 bits
    spare = spare & maskChar(2, 3);

    //right shifts 5 bits
    spare = RshiftChar(spare, 3);

    return spare;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetBearerC1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of bearerC1 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBCap    : The variable containing the value of ext1,spare1 and
//                bearerC1
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrBearerCapabilityGetBearerC1(unsigned char sIeBCap)
{
    UInt8 bearerC1 = sIeBCap;

    //clears last 7 bits
    bearerC1 = bearerC1 & maskChar(4, 8);

    return bearerC1;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetExt2()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext2 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// RETURN       : BOOL
// **/
static BOOL SaalIEBrBearerCapabilityGetExt2(unsigned char sIeBearerCap)
{
    unsigned char ext2 = sIeBearerCap;

    //clears last 7 bits
    ext2 = ext2 & maskChar(1, 1);

    //right shifts 7 bits
    ext2 = RshiftChar(ext2, 1);

    return (BOOL)ext2;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetSpare2()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of spare2 for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrBearerCapabilityGetSpare2(unsigned char sIeBearerCap)
{
    UInt8 spare2 = sIeBearerCap;

    //clears last 7 bits
    spare2 = spare2 & maskChar(2, 3);

    //right shifts 5 bits
    spare2 = RshiftChar(spare2, 3);

    return spare2;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetTrType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of TrType for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrBearerCapabilityGetTrType(unsigned char sIeBearerCap)
{
    UInt8 TrType = sIeBearerCap;

    //clears all except 4-6 bits
    TrType = TrType & maskChar(4, 6);

    //right shifts 2 bits
    TrType = RshiftChar(TrType, 6);

    return TrType;
}


// /**
// FUNCTION    :: SaalIEBrBearerCapabilityGetTimeRq()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of TimeRq for SaalIEBrBearerCapability
// PARAMETERS  ::
// + sIeBearerCap : The variable containing the value of ext2,spare2,TrType
//                  and TimeRq.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrBearerCapabilityGetTimeRq(unsigned char sIeBearerCap)
{
    UInt8 TimeRq = sIeBearerCap;

    //clears all except 7-8 bits
    TimeRq = TimeRq & maskChar(7, 8);

    return TimeRq;
}



// /**
// STRUCT      :: SaalIEBrHighLayerInfo
// DESCRIPTION :: Information element Broadband high layer info
// **/
typedef struct struct_saal_iebr_high_layer_info
{
    SaalInformationElement ieField;
    unsigned char sIeHlInfo;//ext:1, HighLrInfoType:7;
    unsigned int HighLayerInfo1;
    unsigned int HighLayerInfo2;
} SaalIEBrHighLayerInfo;


// /**
// FUNCTION    :: SaalIEBrHighLayerInfoSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalIEBrHighLayerInfo
// PARAMETERS  ::
// + sIeHlInfo  : The variable containing the value of ext and
//                HighLrInfoType.
// + ext        : Input value for set operation
// RETURN       :: void
// **/
static void SaalIEBrHighLayerInfoSetExt(unsigned char *sIeHlInfo, BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears first bit
    *sIeHlInfo = *sIeHlInfo & maskChar(2, 8);

    //setting the value of ext in sIeHlInfo
    *sIeHlInfo = *sIeHlInfo | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIEBrHighLayerInfoSetHLInfoType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of HighLrInfoType for SaalIEBrHighLayerInfo
// PARAMETERS  ::
// + sIeHlInfo  : The variable containing the value of ext and
//                HighLrInfoType.
// + hliType    : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrHighLayerInfoSetHLInfoType(unsigned char *sIeHlInfo,
                                               unsigned char hliType)
{
    //masks hliType within boundry range
    hliType = hliType & maskChar(2, 8);

    //clears last seven bits
    *sIeHlInfo = *sIeHlInfo & maskChar(1, 1);

    //setting the value of HighLrInfoType in sIeHlInfo
    *sIeHlInfo = *sIeHlInfo | hliType;
}


// /**
// FUNCTION    :: SaalIEBrHighLayerInfoGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalIEBrHighLayerInfo
// PARAMETERS  ::
// + sIeHlInfo  : The variable containing the value of ext and
//                HighLrInfoType.
// RETURN       : BOOL
// **/
static BOOL SaalIEBrHighLayerInfoGetExt(unsigned char sIeHlInfo)
{
    unsigned char ext = sIeHlInfo;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIEBrHighLayerInfoGetHLInfoType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of HighLrInfoType for
//                SaalIEBrHighLayerInfo
// PARAMETERS  ::
// + sIeHlInfo  : The variable containing the value of ext and
//                HighLrInfoType.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrHighLayerInfoGetHLInfoType(unsigned char sIeHlInfo)
{
    UInt8 hliType = sIeHlInfo;

    //clears the first bit
    hliType = hliType & maskChar(2, 8);

    return hliType;
}


// /**
// STRUCT      :: SaalIEBrLowLayerInfo
// DESCRIPTION :: Information element Broadband low layer info
// **/
typedef struct struct_saal_iebr_low_layer_info
{
    SaalInformationElement ieField;
    unsigned char sIeBllInfo1;//ext1:1,
                    //layer1Id:2,
                    //layer1Protocol:5;
    unsigned char sIeBllInfo2;//ext2:1,
                    //layer2Id:2,
                    //layer2Protocol:5;
    unsigned char sIeBllInfo3;//ext3:1,
                    //layer3Id:2,
                    //layer3Protocol:5;
} SaalIEBrLowLayerInfo;

// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetExt1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext1 for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo1 : The variable containing the value of ext1,layer1Id and
//                 layer1Protocol.
// + ext         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetExt1(unsigned char *sIeBllInfo1,
                                        BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext1 within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears first bit
    *sIeBllInfo1 = *sIeBllInfo1 & maskChar(2, 8);

    //setting the value of ext1 in sIeBllInfo1
    *sIeBllInfo1 = *sIeBllInfo1 | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetLayer1Id()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of layer1Id for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo1 : The variable containing the value of ext1,layer1Id and
//                 layer1Protocol.
// + layerId     : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetLayer1Id(unsigned char *sIeBllInfo1,
                                            unsigned char layerId)
{
    //masks layerId1 within boundry range
    layerId = layerId & maskChar(7, 8);

    //clears 2-3 bits
    *sIeBllInfo1 = *sIeBllInfo1 & (~(maskChar(2, 3)));

    //setting the value of layer1Id in sIeBllInfo1
    *sIeBllInfo1 = *sIeBllInfo1 | LshiftChar(layerId, 3);
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetLayer1Protocol()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of layer1Protocol for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo1   : The variable containing the value of ext1,layer1Id and
//                   layer1Protocol.
// + layerProtocol : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetLayer1Protocol(unsigned char *sIeBllInfo1,
                                                 unsigned char layerProtocol)
{
    //masks layerProtocol1 within boundry range
    layerProtocol = layerProtocol & maskChar(4, 8);

    //clears last 5 bits
    *sIeBllInfo1 = *sIeBllInfo1 & maskChar(1, 3);

    //setting the value of layer1Protocol in sIeBllInfo1
    *sIeBllInfo1 = *sIeBllInfo1 | layerProtocol;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetExt2()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext2 for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo2 : The variable containing the value of ext2,layer2Id and
//                 layer2Protocol.
// + ext         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetExt2(unsigned char *sIeBllInfo2,
                                        BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext2 within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears first bit
    *sIeBllInfo2 = *sIeBllInfo2 & maskChar(2, 8);

    //setting the value of ext2 in sIeBllInfo2
    *sIeBllInfo2 = *sIeBllInfo2 | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetLayer2Id()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of layer2Id for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo2 : The variable containing the value of ext2,layer2Id and
//                 layer2Protocol.
// + layerId     : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetLayer2Id(unsigned char *sIeBllInfo2,
                                            unsigned char layerId)
{
    //masks layerId2 within boundry range
    layerId = layerId & maskChar(7, 8);

    //clears 2-3 bits
    *sIeBllInfo2 = *sIeBllInfo2 & (~(maskChar(2, 3)));

    //setting the value of layer2Id in sIeBllInfo2
    *sIeBllInfo2 = *sIeBllInfo2 | LshiftChar(layerId, 3);
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetLayer2Protocol()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of layer2Protocol for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo2   : The variable containing the value of ext2,layer2Id and
//                   layer2Protocol.
// + layerProtocol : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetLayer2Protocol(unsigned char *sIeBllInfo2,
                                                 unsigned char layerProtocol)
{
    //masks layerProtocol2 within boundry range
    layerProtocol = layerProtocol & maskChar(4, 8);

    //clears last 5 bits
    *sIeBllInfo2 = *sIeBllInfo2 & maskChar(1, 3);

    //setting the value of layer2Protocol in sIeBllInfo2
    *sIeBllInfo2 = *sIeBllInfo2 | layerProtocol;
}



// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetExt3()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext3 for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo3 : The variable containing the value of ext3,layer3Id and
//                 layer3Protocol.
// + ext         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetExt3(unsigned char *sIeBllInfo3,
                                        BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext3 within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears first bit
    *sIeBllInfo3 = *sIeBllInfo3 & maskChar(2, 8);

    //setting the value of ext3 in sIeBllInfo3
    *sIeBllInfo3 = *sIeBllInfo3 | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetLayer3Id()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of layer3Id for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo3 : The variable containing the value of ext3,layer3Id and
//                 layer3Protocol.
// + layerId     : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetLayer3Id(unsigned char *sIeBllInfo3,
                                            unsigned char layerId)
{
    //masks layerId3 within boundry range
    layerId = layerId & maskChar(7, 8);

    //clears 2-3 bits
    *sIeBllInfo3 = *sIeBllInfo3 & (~(maskChar(2, 3)));

    //setting the value of layer3Id in sIeBllInfo3
    *sIeBllInfo3 = *sIeBllInfo3 | LshiftChar(layerId, 3);
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoSetLayer3Protocol()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of layer3Protocol for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo3   : The variable containing the value of ext3,layer3Id and
//                   layer3Protocol.
// + layerProtocol : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIEBrLowLayerInfoSetLayer3Protocol(unsigned char *sIeBllInfo3,
                                                 unsigned char layerProtocol)
{
    //masks layerProtocol3 within boundry range
    layerProtocol = layerProtocol & maskChar(4, 8);

    //clears last 5 bits
    *sIeBllInfo3 = *sIeBllInfo3 & maskChar(1, 3);

    //setting the value of layer3Protocol in sIeBllInfo3
    *sIeBllInfo3 = *sIeBllInfo3 | layerProtocol;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetExt1()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext1 for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo1 : The variable containing the value of ext1,layer1Id and
//                 layer1Protocol.
// RETURN       : BOOL
// **/
static BOOL SaalIEBrLowLayerInfoGetExt1(unsigned char sIeBllInfo1)
{
    unsigned char ext = sIeBllInfo1;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetLayer1Id()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of layer1Id for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo1 : The variable containing the value of ext1,layer1Id and
//                 layer1Protocol.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrLowLayerInfoGetLayer1Id(unsigned char sIeBllInfo1)
{
    UInt8 layerId = sIeBllInfo1;

    //clears sll except 2-3 bits
    layerId = layerId & maskChar(2, 3);

    //right shifts 5 bits
    layerId = RshiftChar(layerId, 3);

    return layerId;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetLayer1Protocol()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of layer1Protocol for
//                SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo1 : The variable containing the value of ext1,layer1Id and
//                 layer1Protocol.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrLowLayerInfoGetLayer1Protocol(unsigned char sIeBllInfo1)
{
    UInt8 layerProtocol = sIeBllInfo1;

    //clears first 3 bits
    layerProtocol = layerProtocol & maskChar(4, 8);

    return layerProtocol;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetExt2()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext2 for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo2 : The variable containing the value of ext2,layer2Id and
//                 layer2Protocol.
// RETURN       : BOOL
// **/
static BOOL SaalIEBrLowLayerInfoGetExt2(unsigned char sIeBllInfo2)
{
    unsigned char ext = sIeBllInfo2;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetLayer2Id()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of layer2Id for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo2 : The variable containing the value of ext2,layer2Id and
//                 layer2Protocol.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrLowLayerInfoGetLayer2Id(unsigned char sIeBllInfo2)
{
    UInt8 layerId = sIeBllInfo2;

    //clears sll except 2-3 bits
    layerId = layerId & maskChar(2, 3);

    //right shifts 5 bits
    layerId = RshiftChar(layerId, 3);

    return layerId;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetLayer2Protocol()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of layer2Protocol for
//                SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo2 : The variable containing the value of ext2,layer2Id and
//                 layer2Protocol.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrLowLayerInfoGetLayer2Protocol(unsigned char sIeBllInfo2)
{
    UInt8 layerProtocol = sIeBllInfo2;

    //clears first 3 bits
    layerProtocol = layerProtocol & maskChar(4, 8);

    return layerProtocol;
}



// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetExt3()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext3 for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo3 : The variable containing the value of ext3,layer3Id and
//                 layer3Protocol.
// RETURN       : BOOL
// **/
static BOOL SaalIEBrLowLayerInfoGetExt3(unsigned char sIeBllInfo3)
{
    unsigned char ext = sIeBllInfo3;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetLayer3Id()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of layer3Id for SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo3 : The variable containing the value of ext3,layer3Id and
//                 layer3Protocol.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrLowLayerInfoGetLayer3Id(unsigned char sIeBllInfo3)
{
    UInt8 layerId = sIeBllInfo3;

    //clears sll except 2-3 bits
    layerId = layerId & maskChar(2, 3);

    //right shifts 5 bits
    layerId = RshiftChar(layerId, 3);

    return layerId;
}


// /**
// FUNCTION    :: SaalIEBrLowLayerInfoGetLayer3Protocol()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of layer3Protocol for
//                SaalIEBrLowLayerInfo
// PARAMETERS  ::
// + sIeBllInfo3 : The variable containing the value of ext3,layer3Id and
//                 layer3Protocol.
// RETURN       : UInt8
// **/
static UInt8 SaalIEBrLowLayerInfoGetLayer3Protocol(unsigned char sIeBllInfo3)
{
    UInt8 layerProtocol = sIeBllInfo3;

    //clears first 3 bits
    layerProtocol = layerProtocol & maskChar(4, 8);

    return layerProtocol;
}



// /**
// STRUCT      :: SaalIECallStateInfo
// DESCRIPTION :: Information element Call state Information Element
// **/

typedef struct struct_saal_iecallstate_info
{
    SaalInformationElement ieField;
    unsigned char saalIeSInfo;//spare:2,
                    //callStateValue:6;
} SaalIECallStateInfo;

// /**
// FUNCTION    :: SaalIECallStateInfoSetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of spare for SaalIECallStateInfo
// PARAMETERS  ::
// + saalIeSInfo : The variable containing the value of spare and
//                 callStateValue
// + spare       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallStateInfoSetSpare(unsigned char *saalIeSInfo,
                                        unsigned char spare)
{
    //masks spare within boundry range
    spare = spare & maskChar(7, 8);

    //clears the first and second bit
    *saalIeSInfo = *saalIeSInfo & maskChar(3, 8);

    //setting the value of spare in saalIeSInfo
    *saalIeSInfo = *saalIeSInfo | LshiftChar(spare, 2);
}


// /**
// FUNCTION    :: SaalIECallStateInfoSetCallStateValue()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of callStateValue for SaalIECallStateInfo
// PARAMETERS  ::
// + saalIeSInfo : The variable containing the value of spare and
//                 callStateValue
// + csv         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallStateInfoSetCallStateValue(unsigned char *saalIeSInfo,
                                                 unsigned char csv)
{
    //masks callStateValue within boundry range
    csv = csv & maskChar(3, 8);

    //clears the first and second bit
    *saalIeSInfo = *saalIeSInfo & maskChar(3, 8);

    //setting the value of callStateValue in saalIeSInfo
    *saalIeSInfo = *saalIeSInfo | csv;
}


// /**
// FUNCTION    :: SaalIECallStateInfoGetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of spare for SaalIECallStateInfo
// PARAMETERS  ::
// + saalIeSInfo : The variable containing the value of spare and
//                 callStateValue
// RETURN       : UInt8
// **/
static UInt8 SaalIECallStateInfoGetSpare(unsigned char saalIeSInfo)
{
    UInt8 spare = saalIeSInfo;

    //clears all the bits except first 2
    spare = spare & maskChar(1, 2);

    //right shifts 2 bits
    spare = RshiftChar(spare, 2);

    return spare;
}


// /**
// FUNCTION    :: SaalIECallStateInfoGetCallStateValue()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of callStateValue for SaalIECallStateInfo
// PARAMETERS  ::
// + saalIeSInfo : The variable containing the value of spare and
//                 callStateValue
// RETURN       : UInt8
// **/
static UInt8 SaalIECallStateInfoGetCallStateValue(unsigned char saalIeSInfo)
{
    UInt8 csv = saalIeSInfo;

    //clears first 2 bits
    csv = csv & maskChar(3, 8);

    return csv;
}


// /**
// STRUCT      :: SaalIECalledPartyNumber
// DESCRIPTION :: Information element CalledParty Number
// **/
typedef struct struct_saal_iecalledparty_number
{
    SaalInformationElement ieField;
    unsigned char sIeCalledPn;//ext:1,
                    //typeOfNumber:3,
                    //AddrPlanId:4;
    unsigned char sIeCalledPnum;//flag:1,
                    //numberDigit:7;
    AtmAddress CalledPartyNum;
} SaalIECalledPartyNumber;


// /**
// FUNCTION    :: SaalIECalledPartyNumberSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPn : The variable containing the value of ext,typeOfNumber
//                 and AddrPlanId.
// + ext         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartyNumberSetExt(unsigned char *sIeCalledPn,
                                          BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears the first bit
    *sIeCalledPn = *sIeCalledPn & maskChar(2, 8);

    //setting the value of ext in sIeCalledPn
    *sIeCalledPn = *sIeCalledPn | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberSetTypeOfNum()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of typeOfNumber for SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPn  : The variable containing the value of ext,typeOfNumber
//                  and AddrPlanId.
// + typeOfNumber : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartyNumberSetTypeOfNum(unsigned char *sIeCalledPn,
                                                unsigned char ton)
{
    //masks ton within boundry range
    ton = ton & maskChar(6, 8);

    //clears the 2-4 bit
    *sIeCalledPn = *sIeCalledPn & (~(maskChar(2, 4)));

    //setting the value of typeOfNumber in sIeCalledPn
    *sIeCalledPn = *sIeCalledPn | LshiftChar(ton, 4);
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberSetAddrPlanId()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of AddrPlanId for SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPn : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId.
// + apid        : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartyNumberSetAddrPlanId(unsigned char *sIeCalledPn,
                                                 unsigned char apid)
{
    //masks apid within boundry range
    apid = apid & maskChar(5, 8);

    //clears the 4-8 bit
    *sIeCalledPn = *sIeCalledPn & maskChar(1, 4);

    //setting the value of AddrPlanId in sIeCalledPn
    *sIeCalledPn = *sIeCalledPn | apid;
}



// /**
// FUNCTION    :: SaalIECalledPartyNumberSetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of Flag for SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPnum : The variable containing the value of Flag and
//                   numberDigit.
// + flag          : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartyNumberSetFlag(unsigned char *sIeCalledPnum,
                                           BOOL flag)
{
    unsigned char flag_char = (unsigned char) flag;

    //masks flag within boundry range
    flag_char = flag_char & maskChar(8, 8);

    //clears first bit
    *sIeCalledPnum = *sIeCalledPnum & maskChar(2, 8);

    //setting the value of flag in sIeCalledPnum
    *sIeCalledPnum = *sIeCalledPnum | LshiftChar(flag_char, 1);
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberSetNumberDigit()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of numberDigit for SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPnum : The variable containing the value of Flag and
//                   numberDigit.
// + numDigit      : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartyNumberSetNumberDigit(
    unsigned char *sIeCalledPnum, unsigned char numDigit)
{
    //masks numDigit within boundry range
    numDigit = numDigit & maskChar(2, 8);

    //clears last seven bits
    *sIeCalledPnum = *sIeCalledPnum & maskChar(1, 1);

    //setting the value of numberDigit in sIeCalledPnum
    *sIeCalledPnum = *sIeCalledPnum | numDigit;
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPn : The variable containing the value of ext,typeOfNumber
//                 and AddrPlanId.
// RETURN       : BOOL
// **/
static BOOL SaalIECalledPartyNumberGetExt(unsigned char sIeCalledPn)
{
    unsigned char ext = sIeCalledPn;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberGetTypeOfNum()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of typeOfNumber for
//                SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPn : The variable containing the value of ext,typeOfNumber
//                 and AddrPlanId.
// RETURN       : UInt8
// **/
static UInt8 SaalIECalledPartyNumberGetTypeOfNum(unsigned char sIeCalledPn)
{
    UInt8 ton = sIeCalledPn;

    //clears all the bits except 2-4
    ton = ton & maskChar(2, 4);

    //right shifts 4 bits
    ton = RshiftChar(ton, 4);

    return ton;
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberGetAddrPlanId()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of AddrPlanId for
//                SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPn : The variable containing the value of ext,typeOfNumber
//                 and AddrPlanId.
// RETURN       : UInt8
// **/
static UInt8 SaalIECalledPartyNumberGetAddrPlanId(unsigned char sIeCalledPn)
{
    UInt8 apid = sIeCalledPn;

    //clears all the bits except 5-8
    apid = apid & maskChar(5, 8);

    return apid;
}

// /**
// FUNCTION    :: SaalIECalledPartyNumberGetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of Flag for
//                SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPnum : The variable containing the value of Flag and
//                   numberDigit.
// RETURN       : BOOL
// **/
static BOOL SaalIECalledPartyNumberGetFlag(unsigned char sIeCalledPnum)
{
    unsigned char flag = sIeCalledPnum;

    //clears last 7 bits
    flag = flag & maskChar(1, 1);

    //right shifts 1 bits
    flag = RshiftChar(flag, 1);

    return (BOOL)flag;
}


// /**
// FUNCTION    :: SaalIECalledPartyNumberGetNumberDigit()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of numberDigit for
//                SaalIECalledPartyNumber
// PARAMETERS  ::
// + sIeCalledPnum : The variable containing the value of Flag and
//                   numberDigit.
// RETURN       : UInt8
// **/
static UInt8 SaalIECalledPartyNumberGetNumberDigit(
    unsigned char sIeCalledPnum)
{
    UInt8 numDigit = sIeCalledPnum;

    //clears the first bit
    numDigit = numDigit & maskChar(2, 8);

    return numDigit;
}


// /**
// STRUCT      :: SaalIECallingPartyNumber
// DESCRIPTION :: Information element CallingParty Number
// **/
typedef struct struct_saal_iecallingparty_number
{
    SaalInformationElement ieField;
    unsigned char   sIeCallingPn;//ext:1,
                    //typeOfNumber:3,
                    //AddrPlanId:4;
    unsigned char sIeCallingPnum;//flag:1,
                    //numberDigit:7;
    AtmAddress CallingPartyNum;
} SaalIECallingPartyNumber;


// /**
// FUNCTION    :: SaalIECallingPartyNumberSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalIECallingPartyNumber
// PARAMETERS  ::
/// + sIeCallingPn  : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId.
// + ext            : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartyNumberSetExt(unsigned char *sIeCallingPn,
                                           BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears the first bit
    *sIeCallingPn = *sIeCallingPn & maskChar(2, 8);

    //setting the value of ext in sIeCallingPn
    *sIeCallingPn = *sIeCallingPn | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberSetTypeOfNum()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of typeOfNumber for SaalIECallingPartyNumber
// PARAMETERS  ::
/// + sIeCallingPn  : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId.
// + ton            : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartyNumberSetTypeOfNum(unsigned char *sIeCallingPn,
                                                 unsigned char ton)
{
    //masks ton within boundry range
    ton = ton & maskChar(6, 8);

    //clears the 2-4 bit
    *sIeCallingPn = *sIeCallingPn & (~(maskChar(2, 4)));

    //setting the value of typeOfNumber in sIeCallingPn
    *sIeCallingPn = *sIeCallingPn | LshiftChar(ton, 4);
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberSetAddrPlanId()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of AddrPlanId for SaalIECallingPartyNumber
// PARAMETERS  ::
/// + sIeCallingPn  : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId.
// + apid           : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartyNumberSetAddrPlanId(
    unsigned char *sIeCallingPn, unsigned char apid)
{
    //masks apid within boundry range
    apid = apid & maskChar(5, 8);

    //clears the 4-8 bit
    *sIeCallingPn = *sIeCallingPn & maskChar(1, 4);

    //setting the value of AddrPlanId in sIeCallingPn
    *sIeCallingPn = *sIeCallingPn | apid;
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberSetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of Flag for SaalIECallingPartyNumber
// PARAMETERS  ::
// + sIeCallingPnum : The variable containing the value of Flag and
//                    numberDigit.
// + flag           : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartyNumberSetFlag(unsigned char *sIeCallingPnum,
                                            BOOL flag)
{
    unsigned char flag_char = (unsigned char) flag;

    //masks flag within boundry range
    flag_char = flag_char & maskChar(8, 8);

    //clears first bit
    *sIeCallingPnum = *sIeCallingPnum & maskChar(2, 8);

    //setting the value of flag in sIeCallingPnum
    *sIeCallingPnum = *sIeCallingPnum | LshiftChar(flag_char, 1);
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberSetNumberDigit()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of numberDigit for SaalIECallingPartyNumber
// PARAMETERS  ::
// + sIeCallingPnum : The variable containing the value of Flag and
//                    numberDigit.
// + numdig         : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartyNumberSetNumberDigit(
    unsigned char *sIeCallingPnum, unsigned char numdig)
{
    //masks numdig within boundry range
     numdig = numdig & maskChar(2, 8);

    //clears last seven bits
    *sIeCallingPnum = *sIeCallingPnum & maskChar(1, 1);

    //setting the value of numberDigit in sIeCallingPnum
    *sIeCallingPnum = *sIeCallingPnum | numdig;
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalIECallingPartyNumber
// PARAMETERS  ::
/// + sIeCallingPn  : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId.
// RETURN       : BOOL
// **/
static BOOL SaalIECallingPartyNumberGetExt(unsigned char sIeCallingPn)
{
    unsigned char ext = sIeCallingPn;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberGetTypeOfNum()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of typeOfNumber for
//                SaalIECallingPartySubAddr
// PARAMETERS  ::
/// + sIeCallingPn  : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId
// RETURN       : UInt8
// **/
static UInt8 SaalIECallingPartyNumberGetTypeOfNum(unsigned char sIeCallingPn)
{
    UInt8 ton = sIeCallingPn;

    //clears all the bits except 2-4
    ton = ton & maskChar(2, 4);

    //right shifts 4 bits
    ton = RshiftChar(ton, 4);

    return ton;
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberGetAddrPlanId()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of AddrPlanId for
//                SaalIECallingPartySubAddr
// PARAMETERS  ::
/// + sIeCallingPn  : The variable containing the value of ext,typeOfNumber
//                    and AddrPlanId.
// RETURN       : UInt8
// **/
static UInt8 SaalIECallingPartyNumberGetAddrPlanId(
    unsigned char sIeCallingPn)
{
    UInt8 apid = sIeCallingPn;

    //clears all the bits except 5-8
    apid = apid & maskChar(5, 8);

    return apid;
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberGetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of Flag for
//                SaalIECallingPartyNumber
// PARAMETERS  ::
// + sIeCallingPnum : The variable containing the value of Flag and
//                    numberDigit
// RETURN       : BOOL
// **/
static BOOL SaalIECallingPartyNumberGetFlag(unsigned char sIeCallingPnum)
{
    unsigned char flag = sIeCallingPnum;

    //clears last 7 bits
    flag = flag & maskChar(1, 1);

    //right shifts 1 bits
    flag = RshiftChar(flag, 1);

    return (BOOL)flag;
}


// /**
// FUNCTION    :: SaalIECallingPartyNumberGetNumberDigit()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of numberDigit for
//                SaalIECallingPartyNumber
// PARAMETERS  ::
// + sIeCallingPnum : The variable containing the value of Flag and
//                    numberDigit
// RETURN       : UInt8
// **/
static UInt8 SaalIECallingPartyNumberGetNumberDigit(
    unsigned char sIeCallingPnum)
{
    UInt8 numdig = sIeCallingPnum;

    //clears the first bit
    numdig = numdig & maskChar(2, 8);

    return numdig;
}


// /**
// STRUCT      :: SaalIECallingPartySubAddr
// DESCRIPTION :: Information Element Calling party sub-address
// **/
typedef struct struct_saal_iecallingparty_subaddr
{
    SaalInformationElement ieField;
    unsigned char sIeCalling;//ext:1,
                    //type:3,
                    //indicator:1,
                    //spare:3;
    Address callingPartyAddr;
} SaalIECallingPartySubAddr;

// /**
// FUNCTION    :: SaalIECallingPartySubAddrSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// +  ext       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartySubAddrSetExt(unsigned char *sIeCalling,
                                            BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears the first bit
    *sIeCalling = *sIeCalling & maskChar(2, 8);

    //setting the value of ext in sIeCalling
    *sIeCalling = *sIeCalling | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrSetType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of type for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// + type       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartySubAddrSetType(unsigned char *sIeCalling,
                                             unsigned char type)
{
    //masks type within boundry range
    type = type & maskChar(6, 8);

    //clears the 2-4 bit
    *sIeCalling = *sIeCalling & (~(maskChar(2, 4)));

    //setting the value of type in sIeCalling
    *sIeCalling = *sIeCalling | LshiftChar(type, 4);
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrSetIndicator()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of indicator for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// + ind        : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartySubAddrSetIndicator(unsigned char *sIeCalling,
                                                  BOOL ind)
{
    unsigned char ind_char = (unsigned char) ind;

    //masks ind within boundry range
    ind_char = ind_char & maskChar(8, 8);

    //clears the fifth bit
    *sIeCalling = *sIeCalling & (~(maskChar(5, 5)));

    //setting the value of indicator in sIeCalling
    *sIeCalling = *sIeCalling | LshiftChar(ind_char, 5);
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrSetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of spare for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// + spare      : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECallingPartySubAddrSetSpare(unsigned char *sIeCalling,
                                              unsigned char spare)
{
    //masks spare within boundry range
    spare = spare & maskChar(6, 8);

    //clears the first five bit
    *sIeCalling = *sIeCalling & maskChar(1, 5);

    //setting the value of spare in sIeCalling
    *sIeCalling = *sIeCalling | spare;
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : BOOL
// **/
static BOOL SaalIECallingPartySubAddrGetExt(unsigned char sIeCalling)
{
    unsigned char ext = sIeCalling;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrGetType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of type for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : UInt8
// **/
static UInt8 SaalIECallingPartySubAddrGetType(unsigned char sIeCalling)
{
    UInt8 type = sIeCalling;

    //clears all the bits except 2-4
    type = type & maskChar(2, 4);

    //right shifts 4 bits
    type = RshiftChar(type, 4);

    return type;
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrGetIndicator()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of indicator for
//                SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : BOOL
// **/
static BOOL SaalIECallingPartySubAddrGetIndicator(unsigned char sIeCalling)
{
    unsigned char ind = sIeCalling;

    //clears all the bits except fifth
    ind = ind & maskChar(5, 5);

    //right shifts 3 bits
    ind = RshiftChar(ind, 5);

    return (BOOL)ind;
}


// /**
// FUNCTION    :: SaalIECallingPartySubAddrGetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of spare for SaalIECallingPartySubAddr
// PARAMETERS  ::
// + sIeCalling : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : UInt8
// **/
static UInt8 SaalIECallingPartySubAddrGetSpare(unsigned char sIeCalling)
{
    UInt8 spare = sIeCalling;

    //clears first 5 bits
    spare = spare & maskChar(5, 8);

    return spare;
}


// /**
// STRUCT      :: SaalIECalledPartySubAddr
// DESCRIPTION :: Information Element Calling party sub-address
// **/
typedef struct struct_saal_iecalledparty_subaddr
{
    SaalInformationElement ieField;
    unsigned char sIeCalled;//ext:1,
                    //type:3,
                    //indicator:1,
                    //spare:3;
    Address calledPartyAddr;
} SaalIECalledPartySubAddr;

// /**
// FUNCTION    :: SaalIECalledPartySubAddrSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// +  ext       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartySubAddrSetExt(unsigned char *sIeCalled,
                                           BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears the first bit
    *sIeCalled = *sIeCalled & maskChar(2, 8);

    //setting the value of ext in sIeCalled
    *sIeCalled = *sIeCalled | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrSetType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of type for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// + type       : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartySubAddrSetType(unsigned char *sIeCalled,
                                            unsigned char type)
{
    //masks type within boundry range
    type = type & maskChar(6, 8);

    //clears the 2-4 bit
    *sIeCalled = *sIeCalled & (~(maskChar(2, 4)));

    //setting the value of type in sIeCalled
    *sIeCalled = *sIeCalled |LshiftChar(type, 4);
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrSetIndicator()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of indicator for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// + ind        : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartySubAddrSetIndicator(unsigned char *sIeCalled,
                                                 BOOL ind)
{
    unsigned char ind_char = (unsigned char) ind;

    //masks ind within boundry range
    ind_char = ind_char & maskChar(8, 8);

    //clears the fifth bit
    *sIeCalled = *sIeCalled & (~(maskChar(5, 5)));

    //setting the value of indicator in sIeCalled
    *sIeCalled = *sIeCalled | LshiftChar(ind_char, 5);
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrSetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of spare for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare..
// + spare      : Input value for set operation
// RETURN       : void : None
// **/
static void SaalIECalledPartySubAddrSetSpare(unsigned char *sIeCalled,
                                             unsigned char spare)
{
    //masks spare within boundry range
    spare = spare & maskChar(6, 8);

    //clears the first five bit
    *sIeCalled = *sIeCalled & maskChar(1, 5);

    //setting the value of spare in sIeCalled
    *sIeCalled = *sIeCalled | spare;
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : BOOL
// **/
static BOOL SaalIECalledPartySubAddrGetExt(unsigned char sIeCalled)
{
    unsigned char ext = sIeCalled;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bit
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrGetType()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of type for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : BOOL
// **/
static UInt8 SaalIECalledPartySubAddrGetType(unsigned char sIeCalled)
{
    UInt8 type = sIeCalled;

    //clears all the bits except 2-4
    type = type & maskChar(2, 4);

    //right shifts 4 bits
    type = RshiftChar(type, 4);

    return type;
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrGetIndicator()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of indicator for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : BOOL
// **/
static BOOL SaalIECalledPartySubAddrGetIndicator(unsigned char sIeCalled)
{
    unsigned char ind = sIeCalled;

    //clears all the bits except fifth
    ind = ind & maskChar(5, 5);

    //right shifts 3 bits
    ind = RshiftChar(ind, 5);

    return (BOOL)ind;
}


// /**
// FUNCTION    :: SaalIECalledPartySubAddrGetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of spare for SaalIECalledPartySubAddr
// PARAMETERS  ::
// + sIeCalled  : The variable containing the value of ext,type,indicator
//                and spare.
// RETURN       : BOOL
// **/
static UInt8 SaalIECalledPartySubAddrGetSpare(unsigned char sIeCalled)
{
    UInt8 spare = sIeCalled;

    //clears first 5 bits
    spare = spare & maskChar(5, 8);

    return spare;
}


// /**
// STRUCT      :: SaalIEConncIdentifier
// DESCRIPTION :: Information element Connection Identifier
// **/
typedef struct struct_saal_ieconnc_identifier
{
    SaalInformationElement ieField;
    unsigned char sIeIdent;//ext:1,
                    //spare:2,
                    //VPAssocSignalling:2,
                    //preferred:3;
    unsigned char VPI;
    unsigned short VCI;
} SaalIEConncIdentifier;

// /**
// FUNCTION    :: SaalIEConncIdentifierSetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of ext for SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// + ext        : Input value for set operation.
// RETURN       : void : None
// **/
static void SaalIEConncIdentifierSetExt(unsigned char *sIeIdent, BOOL ext)
{
    unsigned char ext_char = (unsigned char) ext;

    //masks ext within boundry range
    ext_char = ext_char & maskChar(8, 8);

    //clears the first bit
    *sIeIdent = *sIeIdent & maskChar(2, 8);

    //setting the value of ext in sIeIdent
    *sIeIdent = *sIeIdent | LshiftChar(ext_char, 1);
}


// /**
// FUNCTION    :: SaalIEConncIdentifierSetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of spare for SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// + spare      : Input value for set operation.
// RETURN       : void : None
// **/
static void SaalIEConncIdentifierSetSpare(unsigned char *sIeIdent,
                                          unsigned char spare)
{
    //masks spare within boundry range
    spare = spare & maskChar(7, 8);

    //clears the second and third bit
    *sIeIdent = *sIeIdent & (~(maskChar(2, 3)));

    //setting the value of spare in sIeIdent
    *sIeIdent = *sIeIdent | LshiftChar(spare, 3);
}


// /**
// FUNCTION    :: SaalIEConncIdentifierSetVPASignal()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of VPAssocSignalling for
//                SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// + vpas       : Input value for set operation.
// RETURN       : void : None
// **/
static void SaalIEConncIdentifierSetVPASignal(unsigned char *sIeIdent,
                                              unsigned char vpas)
{
    //masks vpas within boundry range
    vpas = vpas & maskChar(7, 8);

    //clears the fourth and fifth bit
    *sIeIdent = *sIeIdent & (~(maskChar(4, 5)));

    //setting the value of VPAssocSignalling in sIeIdent
    *sIeIdent = *sIeIdent | LshiftChar(vpas, 5);
}


// /**
// FUNCTION    :: SaalIEConncIdentifierSetPreffered()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of preferred for
//                SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// + pref       : Input value for set operation.
// RETURN       : void : None
// **/
static void SaalIEConncIdentifierSetPreffered(unsigned char *sIeIdent,
                                              unsigned char pref)
{
    //masks pref within boundry range
    pref = pref & maskChar(6, 8);

    //clears the last three bits
    *sIeIdent = *sIeIdent & maskChar(1, 5);

    //setting the value of preferred in sIeIdent
    *sIeIdent = *sIeIdent | pref;
}


// /**
// FUNCTION    :: SaalIEConncIdentifierGetExt()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of ext for SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// RETURN       : BOOL
// **/
static BOOL SaalIEConncIdentifierGetExt(unsigned char sIeIdent)
{
    unsigned char ext = sIeIdent;

    //clears last 7 bits
    ext = ext & maskChar(1, 1);

    //right shifts 7 bits
    ext = RshiftChar(ext, 1);

    return (BOOL)ext;
}


// /**
// FUNCTION    :: SaalIEConncIdentifierGetSpare()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of spare for SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// RETURN       : UInt8
// **/
static UInt8 SaalIEConncIdentifierGetSpare(unsigned char sIeIdent)
{
    UInt8 spare = sIeIdent;

    //clears all the bits except second and third
    spare = spare & maskChar(2, 3);

    //right shifts 5 bits
    spare = RshiftChar(spare, 3);

    return spare;
}


// /**
// FUNCTION    :: SaalIEConncIdentifierGetVPASignal()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of VPAssocSignalling for
//                SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// RETURN       : UInt8
// **/
static UInt8 SaalIEConncIdentifierGetVPASignal(unsigned char sIeIdent)
{
    UInt8 vpas = sIeIdent;

    //clears all the bits except fourth and fifth
    vpas = vpas & maskChar(4, 5);

    //right shifts 3 bits
    vpas = RshiftChar(vpas, 5);

    return vpas;
}


// /**
// FUNCTION    :: SaalIEConncIdentifierGetPreffered()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of preferred for SaalIEConncIdentifier
// PARAMETERS  ::
// + sIeIdent   : The variable containing the value of ext,spare,
//                VPAssocSignalling and preferred.
// RETURN       : UInt8
// **/
static UInt8 SaalIEConncIdentifierGetPreffered(unsigned char sIeIdent)
{
    UInt8 pref = sIeIdent;

    //clears all the bits except second and third
    pref = pref & maskChar(6, 8);

    return pref;
}



// /**
// STRUCT      :: SaalIEEndToEndDelay
// DESCRIPTION :: Information element EndToEnd Transit Delay
// **/
typedef struct struct_saal_ie_endtoenddelay
{
    SaalInformationElement ieField;
    unsigned char cumTransitDelayId;
    unsigned short cumTransitDelay;
    unsigned char maxTransitDelayId;
    unsigned short maxTransitDelay;
} SaalIEEndToEndDelay;


// /**
// STRUCT      :: SaalIEQOSParameter
// DESCRIPTION :: Information element QoS Parameter
// **/
typedef struct struct_saal_ie_qosparameter
{
    SaalInformationElement ieField;

    // As specified
    //unsigned char QOSclassFwd;
    //unsigned char QOSclassBkd;

    // As Used
    unsigned int  qosClass;

} SaalIEQOSParameter;


// /**
// STRUCT      :: SaalIENotificationIndicator
// DESCRIPTION :: Information element Notification Indicator
// **/
typedef struct struct_saal_ienotification_indicator
{
    SaalInformationElement ieField;
    unsigned char QOSclassFwd;
    unsigned char QOSclassBkd;
} SaalIENotificationIndicator;


//----------------------------------------------------------
//             Various message related structure
//----------------------------------------------------------

// /**
// STRUCT      :: SaalMsgHeader
// DESCRIPTION :: Message header for SAAL
// **/
typedef struct struct_saal_msg_header
{
    unsigned char protocolDisclaimer;
    unsigned char callRefLength;
    unsigned char saalMsgHdr;//callRefValue1:7, flag:1;
    unsigned short callRefValue2;
    SaalMsgType messageType; //unsigned char;
    unsigned char messageType1;
    unsigned short messageLength;
} SaalMsgHeader;

// /**
// FUNCTION    :: SaalMsgHeaderSetRefVal()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of callRefValue1 for SaalMsgHeader
// PARAMETERS  ::
// + saalMsgHdr : The variable containing the value of callRefValue1 and
//                flag.
// +  refVal    : Input value for set operation
// RETURN       : void : None
// **/
static void SaalMsgHeaderSetRefVal(unsigned char *saalMsgHdr,
                                   unsigned char refVal)
{
    //masks refVal within boundry range
    refVal = refVal & maskChar(2, 8);

    //clears the first seven bits
    *saalMsgHdr = *saalMsgHdr & maskChar(8, 8);

    //setting the value of callRefValue1 in saalMsgHdr
    *saalMsgHdr = *saalMsgHdr | LshiftChar(refVal, 7);
}


// /**
// FUNCTION    :: SaalMsgHeaderSetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set the value of flag for SaalMsgHeader
// PARAMETERS  ::
// + saalMsgHdr : The variable containing the value of callRefValue1 and
//                flag.
// +  flag      : Input value for set operation
// RETURN       : void : None
// **/
static void SaalMsgHeaderSetFlag(unsigned char *saalMsgHdr, BOOL flag)
{
    unsigned char flag_char = (unsigned char) flag;

    //masks flag within boundry range
    flag_char = flag_char & maskChar(8, 8);

    //clears the last bit
    *saalMsgHdr = *saalMsgHdr & maskChar(1, 7);

    //setting the value of flag in saalMsgHdr
    *saalMsgHdr = *saalMsgHdr | flag_char;
}


// /**
// FUNCTION    :: SaalMsgHeaderGetFlag()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of flag for SaalMsgHeader
// PARAMETERS  ::
// + saalMsgHdr : The variable containing the value of callRefValue1 and
//                  flag.
// RETURN       : BOOL
// **/
static BOOL SaalMsgHeaderGetFlag(unsigned char saalMsgHdr)
{
    unsigned char flag = saalMsgHdr;

    //clears first 7 bits
    flag = flag & maskChar(8, 8);

    return (BOOL)flag;
}


// /**
// FUNCTION    :: SaalMsgHeaderGetRefVal()
// LAYER       :: Adaptation Layer
// PURPOSE     :: Returns the value of callRefValue1 for SaalMsgHeader
// PARAMETERS  ::
// + saalMsgHdr : The variable containing the value of callRefValue1 and
//                  flag.
// RETURN       : UInt8
// **/
static UInt8 SaalMsgHeaderGetRefVal(unsigned char saalMsgHdr)
{
    UInt8 refVal = saalMsgHdr;

    //clears the first bit
    refVal = refVal & maskChar(1, 7);

    //right shifts 1 bit
    refVal = RshiftChar(refVal, 7);

    return refVal;
}


// /**
// STRUCT      :: SaalSetupPacket
// DESCRIPTION :: SAAL setup packet structure.
// **/
typedef struct struct_saal_setup_packet
{
    SaalMsgHeader header;

    // Information Element used for setup
    SaalIEAALParameters  aalIE;
    SaalIEATMTrDescriptor trDesc;
    SaalIEBrBearerCapability brBearerCap;
    SaalIEBrLowLayerInfo brLowLayerInfo;
    SaalIECalledPartyNumber calledPartyNum;
    SaalIECallingPartyNumber callingPartyNum;
    SaalIECallingPartySubAddr callingPartyAddr;
    SaalIECalledPartySubAddr  calledPartyAddr;
    SaalIEConncIdentifier conncId;
    SaalIEQOSParameter qosParam;

    // SaalIEBrHighLayerInfo brHighLayerInfo;
    // SaalIECallStateInfo callState;
    //SaalIEEndToEndDelay endToEndDelay;
} SaalSetupPacket;


// /**
// STRUCT      :: SaalAlertPacket
// DESCRIPTION :: SAAL alert packer structure.
// **/
typedef struct struct_saal_alert_packet
{
    SaalMsgHeader header;

    // Information Element used for Alert
    SaalIEConncIdentifier conncId;

    // Added for inavailibility of ARP
    // this field content the ATM address
    // of the responsible gateway
    // to reach the destination IP

    SaalIECalledPartyNumber calledPartyNum;

    //  Notification indicator

} SaalAlertPacket;


// /**
// STRUCT      :: SaalCallProcPacket
// DESCRIPTION :: SAAL proc-packet for call.
// **/
typedef struct struct_saal_callproc_packet
{
    SaalMsgHeader header;

    // Information Element used for CallProc
    SaalIEConncIdentifier conncId;

   // Notification indicator
} SaalCallProcPacket;


// /**
// STRUCT      :: SaalConnectPacket
// DESCRIPTION :: SAAL connecting packet structure
// **/
typedef struct struct_saal_connect_packet
{
    SaalMsgHeader header;

    // Information Element used for connect
    SaalIEAALParameters  aalIE;
    SaalIEBrLowLayerInfo brLowLayerInfo;
    SaalIEConncIdentifier conncId;
    SaalIEEndToEndDelay endToEndDelay;
} SaalConnectPacket;


// /**
// STRUCT      :: SaalConnectAckPacket
// DESCRIPTION :: Packet structure for acknowledging SAAL connection
// **/
typedef struct struct_saal_connect_ackpacket
{
    SaalMsgHeader header;

    // Information Element used for connectAck
    SaalIEConncIdentifier conncId;
} SaalConnectAckPacket;


// /**
// STRUCT      :: SaalReleasePacket
// DESCRIPTION :: Packet structure for acknowledging SAAL connection
// **/
typedef struct struct_saal_releasepacket
{
    SaalMsgHeader header;

    //TBD: need checking
    // Information Element used for release
    SaalIEConncIdentifier conncId;

    // Cause
    // Notification indicator
} SaalReleasePacket;


// /**
// STRUCT      :: SaalReleaseCompletePacket
// DESCRIPTION :: Packet structure for complete release of SAAL connection
// **/
typedef struct struct_saal_release_completepacket
{
    SaalMsgHeader header;

    //TBD: need checking
    // Information Element used for release

    SaalIEConncIdentifier conncId;

   // Cause
} SaalReleaseCompletePacket;


// /**
// STRUCT      :: SaalVPIListItem
// DESCRIPTION :: Packet structure for VPI list item for SAAL.
// **/
typedef struct struct_saal_vpi_listitem
{
    unsigned short VCI;
    int virPathId;
    int pathBW;
    BOOL status;
} SaalVPIListItem;


//----------------------------------------------------------
//        Timer & Aplication specific structure
//----------------------------------------------------------

// /**
// STRUCT      :: SaalStats
// DESCRIPTION :: Various stats for SAAL.
// **/
typedef struct struct_saal_stats
{
    int NumOfAtmSetupSent;
    int NumOfAtmSetupRecv;

    int NumOfAtmCallProcSent;
    int NumOfAtmCallProcRecv;

    int NumOfAtmConnectSent;
    int NumOfAtmConnectRecv;

    int NumOfAtmConnectAckSent;
    int NumOfAtmConnectAckRecv;

    int NumOfAtmAlertSent;
    int NumOfAtmAlertRecv;

    int NumOfAtmReleaseSent;
    int NumOfAtmReleaseRecv;

    int NumOfAtmReleaseCompleteSent;
    int NumOfAtmReleaseCompleteRecv;
} SaalStats;


// /**
// STRUCT      :: SaalInterfaceData
// DESCRIPTION :: Data structure for SAAL interface.
// **/
typedef struct struct_saal_interfacedata
{
    int maxVPI;
    int numVPI;
    LinkedList* vpiList;
} SaalInterfaceData;


// /**
// STRUCT      :: SaalNodeData
// DESCRIPTION :: Data structure for SAAL node.
// **/
typedef struct struct_saal_nodedata
{
    BOOL printSaalStat;
    SaalStats stats;

    LinkedList* appList;
    SaalInterfaceData* saalIntf;
} SaalNodeData;


// /**
// STRUCT      :: SaalTimerData
// DESCRIPTION :: Data structure for SAAL timer.
// **/
typedef struct struct_saal_timerdata
{
    int intfId;
    SaalTimerType type;
    unsigned short VCI;
    unsigned char VPI;
    unsigned char seqNo;
    char* timerPtr;
} SaalTimerData;


// /**
// STRUCT      :: SaalAppData
// DESCRIPTION :: Data structure for SAAL application.
// **/
typedef struct struct_saal_appdata
{
    // Saal Connection specific Info

    SaalCallEndPointType endPointType;
    SaalCallState state;

    // Store the exit & entry point in ATM cloud
    AtmAddress* callingPartyNum;
    AtmAddress* calledPartyNum;

    // Information regarding attached network
    unsigned char attachedNetwork;

    // Store the actual called/calling
    // party address
    Address callingPartyAddr;
    Address calledPartyAddr;

    // Used during call establishment
    int inIntf;
    AtmAddress* prevHopAddr;
    unsigned char VPI;
    unsigned short VCI;

    // Used during call release
    int outIntf;
    AtmAddress* nextHopAddr;
    unsigned char finalVPI;

    // Timer related info
    LinkedList* timerList;

} SaalAppData;


//------------------------------------------------------------------
//                    FUNCTION PROTOTYPE
//------------------------------------------------------------------


// /**
// FUNCTION    :: AtmSAALInit
// LAYER       :: Adaptation Layer
// PURPOSE     :: Innitialization of SAAL in ATM
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalLayerPtr : SaalNodeData** : SAAL layer pointer.
// + nodeInput  : const NodeInput * : Pointer to config file.
// RETURN       : void : None
// **/
void
AtmSAALInit(
    Node *node,
    SaalNodeData** saalLayerPtr,
    const NodeInput *nodeInput);


// /**
// FUNCTION    :: SaalHandleProtocolEvent
// LAYER       :: Adaptation Layer
// PURPOSE     :: Protocol event handelling function for SAAL.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : None
// **/
void
SaalHandleProtocolEvent(
    Node* node,
    Message* msg);


// /**
// FUNCTION    :: SaalHandleProtocolPacket
// LAYER       :: Adaptation Layer
// PURPOSE     :: Protocol packet handelling function for SAAL.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + interfaceIndex : int : interface index.
// RETURN       : void : None
// **/
void
SaalHandleProtocolPacket(
    Node* node,
    Message* msg,
    int interfaceIndex);


// /**
// FUNCTION    :: SaalFinalize
// LAYER       :: Adaptation Layer
// PURPOSE     :: Finalize fnction for SAAL
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void
SaalFinalize(Node* node);


// /**
// FUNCTION    :: SaalStartSignalingProcess
// LAYER       :: Adaptation Layer
// PURPOSE     :: To start signaling process.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : Virtual connection identifire.
// + VPI        : unsigned char :  VPI value for SAAL.
// + srcAddr    : Address : Source address.
// + destAddr   : Address : Destination address.
// RETURN       : void : None
// **/
void
SaalStartSignalingProcess(
    Node *node,
    unsigned short VCI,
    unsigned char VPI,
    Address srcAddr,
    Address destAddr);



#endif
