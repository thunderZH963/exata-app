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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#include "net-snmp-config_netsnmp.h"
#include "netSnmpAgent.h"
#include "tools_netsnmp.h"
#include "snmpv3_netsnmp.h"
#include "scapi_netsnmp.h"
#ifdef JNE_LIB
#include "ittrSrwStats.h"
#include "jne.h"
#endif

oid             RFC1213_MIB[] = { 1, 3, 6, 1, 2, 1 };
static char     Standard_Prefix[] = ".1.3.6.1.2.1";
oid sntOidx[10]= {1,3,6,1,6,3,1,1,4,1};
oid sysup[10]= {1,3,6,1,2,1,1,3,0};
oid snmptrapoid[12] = {1,3,6,1,6,3,1,1,4,1,0};

#define trapv3 1,3,6,1,6,3,1,1,5


/*
 * NAME:        NetSnmpAgent.
 * PURPOSE:     Constructor of NetSnmpAgent Class.
 * PARAMETERS:  none.
 * RETURN:      none.
 */


NetSnmpAgent::NetSnmpAgent()
{
    memset(this, 0, sizeof(NetSnmpAgent));
}


/*
 * NAME:        NetSnmpAgentInit.
 * PURPOSE:     Initialize NetSnmpAgent Class object.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */

void
NetSnmpAgent::NetSnmpAgentInit(Node* node)
{
    memset(this,0,sizeof(NetSnmpAgent));
    this->node = node;
    stores[0]= "LIB";
    stores[1] = "APP";
    stores[2] = "TOK";
    File = "(none)";
    strcpy(version_descr, NETSNMP_VERS_DESC);
    strcpy(sysContact ,NETSNMP_SYS_CONTACT);
    strcpy(sysName, NETSNMP_SYS_NAME);
    strcpy(sysLocation, NETSNMP_SYS_LOC);
    sprintf(SYSTEM_NAME_NETSNMP,"%s",node->hostname);
    sysServices = 72;
    regnum = 1;
    engineIDType = ENGINEID_TYPE_NETSNMP_RND;
    engineIDNic = NULL;
    engineIDIsSet = 0;  /* flag if ID set by config */
    oldEngineID = NULL;
    oldEngineIDLength = 0;
    noNameUser = NULL;
    userList = NULL;
    Reqid = 0;
    Msgid = 0;
    Sessid = 0;
    Transid = 0;
    done_init_agent = 0;
    context_subtrees = NULL;
    netsnmp_agent_queued_list = NULL;
    Sets = NULL;
    netsnmp_processing_set = NULL;
    netsnmp_running = 1;
    com2SecList=NULL;
    com2SecListLast=NULL;

    for (int i = 0; i < node->numberInterfaces; i++)
    {
        node->macData[i]->interfaceState = INTERFACE_UP;
        node->macData[i]->interfaceUpTime = node->getNodeTime();
        node->macData[i]->interfaceDownTime = node->getNodeTime();
    }

    RANDOM_SetSeed(snmpRandomSeed,
                   node->globalSeed,
                   node->nodeId,
                   APP_SNMP_AGENT);

    init_agent("snmpd");
    init_mib_modules();
    init_snmp("snmpd");

}


/*
 * NAME:        setCurrentPacket.
 * PURPOSE:     Copying the packet and packet size received to that of
 *              NetSnmpAgent's object.
 * PARAMETERS:  packet - pointer to the packet.
 *              packetSize - size of the packet received.
 * RETURN:      none.
 */

void
NetSnmpAgent::setCurrentPacket(unsigned char* packet, int packetSize)
{
    currPacket = packet;
    currPacketSize = packetSize;
}


/*
 * NAME:    AsnBuildSequence
 * PURPOSE: builds an ASN header for a sequence with the ID and
 *          length specified.On entry, datalength is input as the
 *          number of valid bytes following "data".  On exit, it
 *          is returned as the number of valid bytes in this object
 *          following the id and length.
 *          This only works on data types < 30, i.e. no extension octets.
 *          The maximum length is 0xFFFF;
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                length - length of object.
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */
unsigned char*
NetSnmpAgent::AsnBuildSequence(unsigned char*  data, int* datalength,
                               unsigned char type, int length)
{
    *datalength -= 4;
    if (*datalength < 0){
        *datalength += 4;   /* fix up before punting */
        return NULL;
    }
    *data++ = type;
    *data++ = (unsigned char)(0x02 | ASN_LONG_LEN);
    *data++ = (unsigned char)((length >> 8) & 0xFF);
    *data++ = (unsigned char)(length & 0xFF);
    return data;
}




/*
 * NAME:    AsnBuildHeaderWithTruth
 * PURPOSE: builds an ASN header for an object with the ID and
 *          length specified.On entry, datalength is input as
 *          the number of valid bytes following "data".  On exit,
 *          it is returned as the number of valid bytes
 *          in this object following the id and length.
 *          This only works on data types < 30, i.e. no
 *          extension octets.The maximum length is 0xFFFF;
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                length - length of object.
                  truth - Whether length is truth.
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */



unsigned char*
NetSnmpAgent::AsnBuildHeaderWithTruth(unsigned char* data, int* datalength,
                    unsigned char type, int length, int truth)
{
  if (*datalength < 1) {
    return(NULL);
  }

  *data++ = type;
  (*datalength)--;
  return(AsnBuildLength(data, datalength, length, truth));
}




/*
 * NAME:    AsnBuildObjId
 * PURPOSE: Builds an ASN object identifier object containing the
 *          input string.On entry, datalength is input as the
            number of valid bytes following "data".  On exit,
            it is returned as the number of valid bytes
 *          following the beginning of the next object.
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                objid - pointer to start of input buffer
 *                objidlength - number of sub-id's in objid
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */

unsigned char*
NetSnmpAgent::AsnBuildObjId(register unsigned char* data, int* datalength,
                            unsigned char type, oid* objid,int objidlength)
{
/*
 * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
    unsigned char buf[MAX_OID_LEN];
    register unsigned char* bp = buf;
    register oid* op = objid;
    int    asnlength;
    register unsigned long subid, mask, testmask;
    register int bits, testbits;
    if (objidlength < 2)
    {
        *bp++ = 0;
        objidlength = 0;
    } else
    {
        *bp++ = (unsigned char) (op[1] + (op[0] * 40));
        objidlength -= 2;
        op += 2;
    }

    while (objidlength-- > 0)
    {
        subid = *op++;
        if (subid < 127)
        { /* off by one? */
            *bp++ = (unsigned char) subid;
        } else
        {
            mask = 0x7F; /* handle subid == 0 case */
            bits = 0;
            /* testmask *MUST* !!!! be of an unsigned type */
            for (testmask = 0x7F, testbits = 0; testmask != 0;
            testmask <<= 7, testbits += 7)
            {
                if (subid & testmask)
                {  /* if any bits set */
                    mask = testmask;
                    bits = testbits;
                }
            }
            /* mask can't be zero here */
            for (;mask != 0x7F; mask >>= 7, bits -= 7){
            /* fix a mask that got truncated above */
                if (mask == 0x1E00000)
                    mask = 0xFE00000;
                *bp++ = (unsigned char)
                        (((subid & mask) >> bits) | ASN_BIT8);
            }
            *bp++ = (unsigned char)(subid & mask);
        }
    }
    asnlength = bp - buf;
    data = AsnBuildHeaderWithTruth(data, datalength, type, asnlength, 1);
    if (data == NULL)
    return NULL;
    if (*datalength < asnlength)
    return NULL;
    memcpy((char*)data, (char*)buf, asnlength);
    *datalength -= asnlength;
    return data + asnlength;
}




/*
 * NAME:    AsnBuildHeader
 * PURPOSE: builds an ASN header for an object with the ID and
 *          length specified.On entry, datalength is input as
 *          the number of valid bytes following "data".  On exit,
 *          it is returned as the number of valid bytes in this
 *          object following the id and length.
 *          This only works on data types < 30, i.e. no extension octets.
 *          The maximum length is 0xFFFF;
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                length - length of object.
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */

 unsigned char*
NetSnmpAgent::AsnBuildHeader(register unsigned char* data, int* datalength,
                             unsigned char type, int length)
{
    if (*datalength < 1)
    return NULL;
    *data++ = type;
    (*datalength)--;
    return AsnBuildLength(data, datalength, length, 0);
}



/*
 * NAME:    AsnBuildNull
 * PURPOSE: Builds an ASN null object.On entry, datalength is
 *          input as the number of valid bytes following "data".
 *          On exit, it is returned as the number of valid bytes
 *          following the beginning of the next object.
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                length - length of object.
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */

unsigned char*
NetSnmpAgent::AsnBuildNull(unsigned char* data, int* datalength,
                           unsigned char type)
{
/*
 * ASN.1 null ::= 0x05 0x00
 */
    return AsnBuildHeaderWithTruth(data, datalength, type, 0, 1);
}


/*
 * NAME:    AsnBuildLength
 * PURPOSE: Build of ASN length.
 * PARAMETERS:   data - pointer to start of object.
 *               datalength - number of valid bytes left in buffer.
 *               truth - Whether length is truth.
 *               length - length of object.
 *  RETURN:      a pointer to the first byte of the
 *               contents of this object.
 *
 */


unsigned char*
NetSnmpAgent::AsnBuildLength(unsigned char* data, int* datalength,
             int length, int truth)
  /*   unsigned char *data;       IN - pointer to start of object */
  /*   int    *datalength; IN/OUT - # of valid bytes left in buf */
  /*   int     length;     IN - length of object */
  /*   int     truth;      IN - If 1, this is the true len. */
{
    unsigned char* start_data = data;

    if (truth)
    { /* no indefinite lengths sent */
        if (length < 0x80)
        {
            if (*datalength < 1)
            {
                return(NULL);
            }
            *data++ = (unsigned char)length;

        } else if (length <= 0xFF)
        {
            if (*datalength < 2)
            {
                return(NULL);
            }
            *data++ = (unsigned char)(0x01 | ASN_LONG_LEN);
            *data++ = (unsigned char)length;
        } else /* 0xFF < length <= 0xFFFF */
        {
            if (*datalength < 3)
            {
                return(NULL);
            }
            *data++ = (unsigned char)(0x02 | ASN_LONG_LEN);
            *data++ = (unsigned char)((length >> 8) & 0xFF);
            *data++ = (unsigned char)(length & 0xFF);
        }

    }
    else
    {
    /* Don't know if this is the true length.  Make sure it's large
     * enough for later.
     */
        if (*datalength < 3)
        {
            return(NULL);
        }
        *data++ = (unsigned char)(0x02 | ASN_LONG_LEN);
        *data++ = (unsigned char)((length >> 8) & 0xFF);
        *data++ = (unsigned char)(length & 0xFF);
    }

    *datalength -= (data - start_data);
    return(data);
}






/*
 * NAME:    AsnBuildString
 * PURPOSE: Builds an ASN octet string object containing the
 *          input string.  On entry, datalength is input as
            the number of valid bytes following "data".  On exit,
            it is returned as the number of valid bytes following
            the beginning of the next object.
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                string - pointer to start of input buffer
 *                strlength - size of input buffer
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */


unsigned char*
NetSnmpAgent::AsnBuildString(unsigned char* data, int* datalength,
             unsigned char type, char* string, int strlength)
{
    /*
    * ASN.1 octet string ::= primstring | cmpdstring
    * primstring ::= 0x04 asnlength byte {byte}*
    * cmpdstring ::= 0x24 asnlength string {string}*
    * This code will never send a compound string.
    */
    data = AsnBuildHeaderWithTruth(data, datalength, type, strlength, 1);
    if (data == NULL)
        return(NULL);

    if (*datalength < strlength)
    {
        //snmp_set_api_error(SNMPERR_ASN_DECODE);
        return(NULL);
    }

    memcpy((char*)data, (char*)string, strlength);
    *datalength -= strlength;
    return(data + strlength);
}


/*
 * NAME:    AsnBuildInt
 * PURPOSE: builds an ASN object containing an integer.
 *          On entry, datalength is input as the number
            of valid bytes following "data".  On exit, it
            is returned as the number of valid bytes following
            the end of this object.
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                intp - pointer to start of integer
 *                intsize - size of *intp
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */


unsigned char*
NetSnmpAgent::AsnBuildInt(unsigned char* data, int* datalength,
              unsigned char type, int* intp, int intsize)
{

  /*
   * ASN.1 integer ::= 0x02 asnlength byte {byte}*
   */
    int integer;
    unsigned int mask;

    if (intsize != sizeof (int))
    {
        //snmp_set_api_error(SNMPERR_ASN_ENCODE);
        return(NULL);
    }

    integer = *intp;

  /*
   * Truncate "unnecessary" bytes off of the most significant end of this
   * 2's complement integer.  There should be no sequence of 9
   * consecutive 1's or 0's at the most significant end of the
   * integer.
   */
    mask = (unsigned int)0x1FF << ((8 * (sizeof(int) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */

    while ((((integer & mask) == 0) || ((integer & mask) == mask))
        && intsize > 1)
    {
        intsize--;
        integer <<= 8;
    }

    data = AsnBuildHeaderWithTruth(data, datalength, type, intsize, 1);
    if (data == NULL)
        return(NULL);

    /* Enough room for what we just encoded? */
    if (*datalength < intsize)
    {
        return(NULL);
    }

    /* Insert it */
    *datalength -= intsize;
    mask = (unsigned int)0xFF << (8 * (sizeof(int) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while (intsize--)
    {
        *data++ = (unsigned char)
                  ((integer & mask) >> (8 *(sizeof(int) - 1)));
        integer <<= 8;
    }
    return(data);
}




/*
 * NAME:    AsnBuildUnsignedInt
 * PURPOSE: builds an ASN object containing an integer.
 *          On entry, datalength is input as the number
            of valid bytes following "data".  On exit,
            it is returned as the number of valid bytes
 *          following the end of this object.
 *  PARAMETERS:   data - pointer to start of object.
 *                datalength - number of valid bytes left in buffer.
 *                type - ASN type of object.
 *                intp - pointer to start of integer
 *                intsize - size of *intp
 *  RETURN:       a pointer to the first byte of the
 *                contents of this object.
 *
 */



unsigned char*
NetSnmpAgent::AsnBuildUnsignedInt(unsigned char*  data, int*  datalength,
                                  char type, unsigned long* intp,
                                  int intsize)
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register unsigned long integer;
    register unsigned long mask;
    int add_null_byte = 0;

    //if (intsize != sizeof (int))
    //    return NULL;
    integer = *intp;
    mask = ((unsigned long)0xFF) << (8 * (sizeof(long) - 1));
    if ((unsigned char)((integer & mask) >>
        (8 * (sizeof(long) - 1))) & 0x80)
    {
        /* if MSB is set */
        add_null_byte = 1;
        intsize++;
    }
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this
     * 2's complement integer.
     * There should be no sequence of 9 consecutive 1's or 0's at the most
     * significant end of the integer.
     */
    else
    {
        mask = ((unsigned long)0x1FF) << ((8 * (sizeof(long) - 1)) - 1);
        while ((((integer & mask) == 0) ||
                ((integer & mask) == mask)) && intsize > 1)
        {
            intsize--;
            integer <<= 8;
        }
    }
    data = AsnBuildHeaderWithTruth(data, datalength, type, intsize, 1);
    if (data == NULL)
        return NULL;
    if (*datalength < intsize)
        return NULL;
    *datalength -= intsize;
    if (add_null_byte == 1)
    {
        *data++ = '\0';
        intsize--;
    }
    mask = ((unsigned long)0xFF) << (8 * (sizeof(long) - 1));
    while (intsize--){
        *data++ = (unsigned char)
                  ((integer & mask) >> (8 * (sizeof(long) - 1)));
    integer <<= 8;
    }
    return data;
}

/*
 * NAME:        Snmpv1SendTrap.
 * PURPOSE:     Prepares a Snmp v1 trap.
 * PARAMETERS:  trapValue - interger value signifying the type of trap to
 *              be send.
 * RETURN:      length of response packet.
 */

int
NetSnmpAgent::Snmpv1SendTrap(int trapValue)
{
#ifdef SNMP_DEBUG
 printf("Snmpv1SendTrap:Snmp v1 Trap formation for node %d\n",node->nodeId);
#endif
    trapValue = trapValue - 1;
    unsigned char* respMesg = response;
    int out_length = SNMP_MAX_MSG_LENGTH;
    int sParam = 0;
    version =0;
    int ver = this->node->snmpVersion -1;
    unsigned char*  out_data;
    trapCommunityLength = 128;

    respMesg = AsnBuildSequence(respMesg, &out_length,
        (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
        0);

    response_version = respMesg;
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(ver), 4);

    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            (char*)"public", strlen("public"));

    response_pdu = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
            (unsigned char)SNMP_PDU_V1TRAP, 0);

    trap_enterprise = respMesg;
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            sntOidx, 10);

    NodeAddress localAddress =
        MAPPING_GetDefaultInterfaceAddressFromNodeId(node, node->nodeId);
    EXTERNAL_hton(&localAddress, sizeof(localAddress));

    respMesg = AsnBuildString(respMesg, &out_length,
            SNMP_IPADDRESS,
            (char*)&localAddress,  4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            (int*)&trapValue, 4);

    sParam = 0;
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &sParam, 4);

    sParam = node->getNodeTime() - *node->startTime;
    respMesg = AsnBuildUnsignedInt(respMesg, &out_length,
            SNMP_TIMETICKS,
            (unsigned long*)&sParam, sizeof(unsigned int));

    out_length = 4;
    respMesg = AsnBuildSequence(respMesg, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
             0);

    out_length = 4;
    out_data = AsnBuildSequence(response, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            (respMesg - response_version));

    out_length = 4;
    if (this->node->snmpVersion == 1)
    {
        out_data = AsnBuildSequence(response_pdu, &out_length,
            SNMP_PDU_V1TRAP, respMesg - trap_enterprise);
    }
    else if (this->node->snmpVersion == 2)
    {
        out_data = AsnBuildSequence(response_pdu, &out_length,
            SNMP_PDU_V2TRAP, respMesg - trap_enterprise);
    }

    response_length = respMesg - response;
    return response_length;
}


/*
 * NAME:        Snmpv2SendTrap.
 * PURPOSE:     Prepares a Snmp v2 trap.
 * PARAMETERS:  trapValue - interger value signifying the type of trap to
 *              be send.
 * RETURN:      length of response packet.
 */

int
NetSnmpAgent::Snmpv2SendTrap(int trapValue)
{
#ifdef SNMP_DEBUG
 printf("Snmpv2SendTrap:Snmp v2c Trap formation for node %d\n",node->nodeId);
#endif
    unsigned char* respMesg = response;
    int out_length = SNMP_MAX_MSG_LENGTH;
    int sParam = 0;
    version =1;
    int errorId = 0;
    int msgid = 2213;
    int ver = this->node->snmpVersion -1;
    unsigned char*  out_data;
    trapCommunityLength = 128;

    respMesg = AsnBuildSequence(respMesg, &out_length,
        (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
        0);


    response_version = respMesg;
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(ver), 4);


    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            (char*)"public", strlen("public"));


    response_pdu = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
            (unsigned char)SNMP_PDU_V2TRAP, 0);

    unsigned char* msgidstart = respMesg;
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(msgid), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(errorId), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(errorId), 4);

    unsigned char* t0 = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
             0);

    unsigned char* t1 = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
             0);

    unsigned char* t2 = respMesg;
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            sysup, 9);

    respMesg = AsnBuildUnsignedInt(respMesg, &out_length,
            SNMP_TIMETICKS,
            (unsigned long*)&sParam, sizeof(unsigned int));

    out_length = 4;
    out_data = AsnBuildSequence(t1, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            (respMesg - t2));

    out_length = SNMP_MAX_MSG_LENGTH;
    unsigned char* t3 = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
             0);

    unsigned char* t4 = respMesg;
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            snmptrapoid, 11);

    oid trapval[12] = {trapv3 , trapValue , 0 };
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            trapval, 11);

    out_length = 4;
    out_data = AsnBuildSequence(t3, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            (respMesg - t4));

    out_length = 4;
    out_data = AsnBuildSequence(t0, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            (respMesg - t1));

    out_length = 4;
    out_data = AsnBuildSequence(response, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            (respMesg - response_version));

    if (this->node->notification_para == SEND_TRAP)
    {
        out_length = 4;
        out_data = AsnBuildSequence(response_pdu, &out_length,
                SNMP_PDU_V2TRAP, respMesg - msgidstart);
    }
    else if (this->node->notification_para == SEND_INFORM)
    {
        out_length = 4;
        out_data = AsnBuildSequence(response_pdu, &out_length,
                SNMP_MSG_INFORM, respMesg - msgidstart);
    }



    response_length = respMesg - response;
    return response_length;
}



/*
 * NAME:        Snmpv3SendTrap.
 * PURPOSE:     Prepares a Snmp v3 trap.
 * PARAMETERS:  trapValue - interger value signifying the type of trap to
 *              be send.
 * RETURN:      length of response packet.
 */

int
NetSnmpAgent::Snmpv3SendTrap(int trapValue)
{
#ifdef SNMP_DEBUG
 printf("Snmpv3SendTrap:Snmp v3 Trap formation for node %d\n",node->nodeId);
#endif
    unsigned char* respMesg = response;
    int out_length = SNMP_MAX_MSG_LENGTH;
    int sParam = 0;
    int version =3;
    unsigned char*  out_data;
    trapCommunityLength = 128;
    int msgid=22008;
    int maxmsgsize=65507;
    char flags[]="5";
    int secmod=3;
    int engboots=2;
    int engtime=0;
    char authpar[]="000000000000000000000000";
    char pripar[]="";
    char contextengid[]="80001f8880104800000db4364c00000000";
    char contextname[]="";
    int requestid=0x6c23;
    int errorstatus=0;
    int errorindex=0;

    struct usmUser* USER = NULL;

    if (userList != NULL)
    {
        USER = userList;
    }
    else
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf (errorString,
            "Since, SNMP-VERSION is configured as 3, therefore, "
            "*.conf should have an user (use createUser)");
        ERROR_ReportError(errorString);
    }

    respMesg = AsnBuildSequence(respMesg, &out_length,
        (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
        0);

    response_version = respMesg;
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(version), 4);


    unsigned char*  MGH = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
        (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    unsigned char*  MGHstart = respMesg;

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(msgid), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(maxmsgsize), 4);

    char*  flag_final;
    flag_final= buildhexstring(flags,strlen(flags));
    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            flag_final, strlen(flags));
   free(flag_final);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(secmod), 4);


    unsigned char*  MSPL = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)
            (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),1, 1);
    unsigned char*  MSPL1 = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);


    unsigned char*  AEIDstart = respMesg;

    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)
            (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            (char*)USER->engineID,  USER->engineIDLen);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)
            (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(engboots), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)
            (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(engtime), 4);

    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)
            (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            USER->secName,strlen(USER->secName));

     unsigned char*  auth_pointer = respMesg;

    char*  auth_final;
    auth_final= buildhexstring(authpar,strlen(authpar));
    respMesg = AsnBuildString(respMesg, &out_length,
                (unsigned char)
                (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                auth_final,12);
    free(auth_final);


    if (strlen(pripar) > 0){
    char*  pripar_final=(char*)malloc(strlen(pripar));
    pripar_final= buildhexstring(pripar,strlen(pripar));
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
               (unsigned char)
               (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
               (strlen(pripar)/2), 1);
    memcpy((char*)respMesg,(char*)pripar_final,(strlen(pripar)/2));
    respMesg=respMesg+(strlen(pripar)/2);
    free(pripar_final);
    }
    else{
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
               (unsigned char)
               (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
               (strlen(pripar)/2), 1);
    }

    *(MSPL+1) = (unsigned char)(respMesg - MSPL1);
    *(MSPL1+1) = (unsigned char)(respMesg - AEIDstart);

    unsigned char*  beforecontextpointer = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

    unsigned char*  beforecontextengine = respMesg;
    char*  contextengid_final;
    contextengid_final= buildhexstring(contextengid,strlen(contextengid));
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
           (unsigned char)
           (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
           (strlen(contextengid)/2), 1);
    memcpy((char*)respMesg,(char*)contextengid_final,
            (strlen(contextengid)/2));
    respMesg=respMesg+(strlen(contextengid)/2);
    free(contextengid_final);

    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            (char*)&contextname, strlen(contextname));

    //if (this->node->notification_para == SEND_TRAP)
    //{
        response_pdu = respMesg;
        respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
                (unsigned char)SNMP_PDU_V2TRAP,1, 1);
    /*}
    else if (this->node->notification_para == SEND_INFORM)
    {
        response_pdu = respMesg;
        respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
                (unsigned char)SNMP_MSG_INFORM,1, 1);
    }*/

    unsigned char*  beforepdu = respMesg;

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(requestid), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(errorstatus), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(errorindex), 4);

    unsigned char*  beforeobjidpointer = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

    unsigned char*  beforeobjidpointer1 = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

    trap_enterprise = respMesg;
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            sysup, 9);

    respMesg = AsnBuildUnsignedInt(respMesg, &out_length,
            SNMP_TIMETICKS,
            (unsigned long*)&sParam, sizeof(unsigned int));

    unsigned char*  beforeobjidpointer2 = respMesg;

    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

    unsigned char*  trap_enterprise1 = respMesg;
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            snmptrapoid, 11);

    oid trapval[12] = {trapv3 , trapValue , 0 };
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            trapval, 11);

    out_length = 4;
    out_data = AsnBuildSequence(response, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            (respMesg - response_version));

    out_length = 4;
    out_data = AsnBuildSequence(MGH, &out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
            MSPL - MGHstart);

    *(beforecontextpointer+1) = (unsigned char)
                                (respMesg - beforecontextengine);
    *(response_pdu+1)         = (unsigned char)
                                (respMesg - beforepdu);
    *(beforeobjidpointer+1)   = (unsigned char)
                                (respMesg - beforeobjidpointer1);
    *(beforeobjidpointer1+1)  = (unsigned char)
                                (beforeobjidpointer2 - trap_enterprise);
    *(beforeobjidpointer2+1)  = (unsigned char)
                                (respMesg - trap_enterprise1);

    response_length = respMesg - response;

    size_t          temp_sig_len = 12;
    u_char*         temp_sig = (u_char*) malloc(temp_sig_len);
    u_char*         proto_msg = response;

    sc_generate_keyed_hash(userList->authProtocol,
                            userList->authProtocolLen,
                            userList->authKey, userList->authKeyLen,
                            proto_msg,response_length,
                            temp_sig, &temp_sig_len);

    memcpy(auth_pointer+2, temp_sig, 12);

     free(temp_sig);

    return response_length;
}

#ifdef JNE_LIB
int
NetSnmpAgent::SendHmsLogoutTrap(int trapValue,
                                netsnmp_variable_list*  vars)
{

     JneData& jneData = JNE_GetJneData(node);
     jneData.sendHmsLoginStatusTrap--;

    unsigned char* respMesg = response;
    int out_length = SNMP_MAX_MSG_LENGTH;
    unsigned long sParam = 0;
    int version =3;
    unsigned char*  out_data;
    trapCommunityLength = 128;
    int msgid=22008;
    int maxmsgsize=65507;
    char flags[]="1";
    int secmod=3;
    int engboots=2;
    int engtime=0;
    char authpar[]="000000000000000000000000";
    char pripar[16]="11111111111111";
    //char contextengid[]="80001F8880D6B3912E0B0B0B4E00000000";
    char contextengid[] = "80001f8801be000102";
    char contextname[]="";
    int requestid=0x6c23;
    int errorstatus=0;
    int errorindex=0;

    requestid = (int) snmp_get_next_reqid();
    msgid = (int) snmp_get_next_msgid();
    if (currentPDU != NULL)
    {
        requestid = (int) currentPDU->reqid;
        msgid = (int) currentPDU->msgid;
    }
    unsigned char* scopedpdu = (unsigned char*) malloc(2000);
    memset(scopedpdu,0,2000);


    memset(response,0,3000);

    oid logintrap_oid[] = { 1,3,6,1,4,1,576,25,3,2,1};
    struct usmUser* USER = NULL;

    if (userList != NULL)
    {  
        USER = userList->next;
        if (vars != NULL)
            if (!memcmp(logintrap_oid, vars->val.objid, 11))
                while (strcmp(USER->name, "UnauthComm") && USER->next != NULL)
                    USER = USER->next;
            else
                while (strcmp(USER->name, "Operator") && USER->next != NULL)
                    USER = USER->next;
    }
    else
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf (errorString,
            "Since, SNMP-VERSION is configured as 3, therefore, "
            "*.conf should have an user (use createUser)");
        ERROR_ReportError(errorString);
    }

    //Retrieve engine data
    u_int boots_uint;
    u_int time_uint;
    get_enginetime(USER->engineID, USER->engineIDLen,
                        &boots_uint, &time_uint, FALSE);
    engboots = boots_uint;
    engtime = time_uint;
    u_int boots_uint_temp = boots_uint;
    EXTERNAL_hton(&boots_uint_temp, sizeof(boots_uint_temp));
    u_int time_uint_temp = time_uint; 
    EXTERNAL_hton(&time_uint_temp, sizeof(time_uint_temp));

    //Insert salt for msgPrivacyParameters field
    u_char salt[BYTESIZE(USM_MAX_SALT_LENGTH)];
    size_t salt_length = BYTESIZE(USM_AES_SALT_LENGTH);        
     
    if (usm_set_aes_iv(salt, &salt_length,
                               boots_uint_temp, time_uint_temp,
                               (unsigned char*) &pripar) == -1)
        printf("Salt error\n");


    //Construct global header
    respMesg = AsnBuildSequence(respMesg, &out_length,
        (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
        0);

    response_version = respMesg;
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(version), 4);


    unsigned char*  MGH = respMesg;
    respMesg = AsnBuildSequence(respMesg, &out_length,
        (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    unsigned char*  MGHstart = respMesg;



    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(msgid), 4);
    //*(response+
    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(maxmsgsize), 4);

    char*  flag_final;
    flag_final= buildhexstring(flags,strlen(flags));
    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            flag_final, strlen(flags));
   free(flag_final);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(secmod), 4);


    unsigned char*  MSPL = respMesg;
    *(response+10) = MSPL - MGHstart;
    *(response+3) = MSPL - response - 4;
    
    
    //Consctruct scoped PDU
    unsigned char*  beforecontextpointer = scopedpdu;
    respMesg = AsnBuildHeaderWithTruth(scopedpdu,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

   
    
    unsigned char*  beforecontextengine = respMesg;
    char*  contextengid_final;
    contextengid_final= buildhexstring(contextengid,strlen(contextengid));
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
           (unsigned char)
           (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
           (strlen(contextengid)/2), 1);
    memcpy((char*)respMesg,(char*)contextengid_final,
            (strlen(contextengid)/2));
    respMesg=respMesg+(strlen(contextengid)/2);
    free(contextengid_final);

    respMesg = AsnBuildString(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            (char*)&contextname, strlen(contextname));

    
    response_pdu = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)SNMP_PDU_V2TRAP,1, 1);

    unsigned char*  beforepdu = respMesg;

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(requestid), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(errorstatus), 4);

    respMesg = AsnBuildInt(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &(errorindex), 4);
    
    unsigned char*  beforeobjidpointer = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

    //OID 1 : SysUpTime
    unsigned char*  beforeobjidpointer1 = respMesg;
    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);
    
    trap_enterprise = respMesg;
    respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            sysup, 9);
    
    sParam = netsnmp_get_agent_uptime(node);
    respMesg = AsnBuildUnsignedInt(respMesg, &out_length,
            SNMP_TIMETICKS,
            (unsigned long*)&sParam, 8); 
      
    //OID 2 : Enterprise Trap ID
    unsigned char*  beforeobjidpointer2 = respMesg;

    respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
            (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);

    unsigned char*  trap_enterprise1 = respMesg;
     
    if (trapValue == -1)    
            respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            snmptrapoid,11);//vars->val.objid, 11);//snmptrapoid, 11);
    else
        respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            snmptrapoid, 11);
            
    //Special case for non generic traps
    //Sets value of enterprise trap to the specific trap's OID
    if (trapValue == -1)
    {
         respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            vars->val.objid, 11);
    }
    else
    {
        oid trapval[12] = {trapv3 , 1 , 0 };
        respMesg = AsnBuildObjId(respMesg, &out_length,
            (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            trapval, 11);
    }
    unsigned char*  beforeobjidpointer3 = respMesg;


    //Loop through list of variable bindings
    int counter = 0;
    unsigned char* beforeoptbind[10];
    unsigned char* optbindoid[10];
    if (trapValue == -1)
    {
        beforeoptbind[counter] = respMesg;
        while (vars->next_variable != NULL)
        {
            
            respMesg = AsnBuildHeaderWithTruth(respMesg,&out_length,
                (unsigned char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),1, 1);
            optbindoid[counter] = respMesg;
            
            vars = vars->next_variable;
            
            respMesg = AsnBuildObjId(respMesg, &out_length,
                (unsigned char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
                vars->name, vars->name_length);

            if (vars->type == ASN_GAUGE || vars->type == ASN_INTEGER)
            {
                respMesg = AsnBuildInt(respMesg, &out_length,
                (unsigned char)(ASN_GAUGE),    
                (int*)vars->val.integer, 4);
            }
            else
            {
                respMesg = AsnBuildString(respMesg, &out_length,
                (unsigned char)(ASN_OCTET_STR),    
                NULL, 0);
            }    
            counter++;
            beforeoptbind[counter] = respMesg;
        }
    }

    
    *(beforecontextpointer+1) = (unsigned char)
                                (respMesg - beforecontextengine);
    *(response_pdu+1)         = (unsigned char)
                                (respMesg - beforepdu);
    *(beforeobjidpointer+1)   = (unsigned char)
                                (respMesg - beforeobjidpointer1);
    //-------------------------------------------------------------------                            
    *(beforeobjidpointer1+1)  = (unsigned char)
                                (beforeobjidpointer2 - trap_enterprise);
    *(beforeobjidpointer2+1)  = (unsigned char) 
                                (beforeobjidpointer3- trap_enterprise1);
    if (trapValue == -1)
    {   
        int i = 0;
        for (i = 0;i < counter;i++)
        {
            *(beforeoptbind[i]+1)  = (unsigned char)
                                    (beforeoptbind[i+1] - optbindoid[i]);
        }
        
        *beforeoptbind[i] = (unsigned char)
                                    (respMesg - optbindoid[i]);
                    
    }
    

    
    

    size_t global_length = MSPL-response;
    size_t scopedpdu_length = respMesg - beforecontextpointer;
    
    
    unsigned char* secParams = (unsigned char*) malloc(1000);
    size_t secParamlen = 0;
    unsigned char* wholeMsg;
    size_t wholeMsgLen = 3000;
    
    int usmgenresult = usm_generate_out_msg(0,(unsigned char*)response,global_length,0,0,USER->engineID,USER->engineIDLen,
                        USER->secName,strlen(USER->secName),SNMP_SEC_LEVEL_AUTHNOPRIV,
                            scopedpdu,scopedpdu_length,NULL, secParams, &secParamlen,
                            &wholeMsg, &wholeMsgLen);  
    if (usmgenresult != SNMPERR_SUCCESS)
        printf("USM_GENERATE_OUT_MSG FAILED!!!\n");
        
    return wholeMsgLen;
}

#endif //JNE_LIB


/*
 * NAME:        buildhexstring.
 * PURPOSE:     Converts a string into another string that contains
 *              corresponding hexadecimal characters.
 * PARAMETERS:  a - String to be converted.
 *              len - length of the String.
 * RETURN:      resulting converted String.
 */



char*
NetSnmpAgent::buildhexstring(char a[],int len)
{
    if (len <= 0) return (char*)a;

    int i,j,L=0;
    char* x;
    char* newa;

    if (len %2 ==0) {L=len;int mm=L/2;  newa=(char*)malloc(L);
                    x=(char*)malloc(mm); }
    else           {L=(len+1);int mm=L/2; newa=(char*)malloc(L);
                    x=(char*)malloc(mm); }


    if (len %2 ==0)  {
        for (i=0;i<len;i++) newa[i]=a[i];
    }
    else {
        newa[0]='0'; for (i=1,j=0;j<len;j++,i++) newa[i]=a[j];
    }




    for (i=0;i<(L/2);i++) x[i]=0;
    int r=0,counter=0;

    for (i=0;i<L;i++)
    {
        char s = 0;
        if (i %2 == 0) r=1; else r=0;

        if (newa[i] == '0') s=0x0;
        else if (newa[i] == '1') s=0x1;
        else if (newa[i] == '2') s=0x2;
        else if (newa[i] == '3') s=0x3;
        else if (newa[i] == '4') s=0x4;
        else if (newa[i] == '5') s=0x5;
        else if (newa[i] == '6') s=0x6;
        else if (newa[i] == '7') s=0x7;
        else if (newa[i] == '8') s=0x8;
        else if (newa[i] == '9') s=0x9;
        else if (newa[i] == 'a' || newa[i] == 'A') s=0xa;
        else if (newa[i] == 'b' || newa[i] == 'B') s=0xb;
        else if (newa[i] == 'c' || newa[i] == 'C') s=0xc;
        else if (newa[i] == 'd' || newa[i] == 'D') s=0xd;
        else if (newa[i] == 'e' || newa[i] == 'E') s=0xe;
        else if (newa[i] == 'f' || newa[i] == 'F') s=0xf;

        s = (char)(s << (4*r));
        x[counter]=x[counter] | s;

        if (i %2 != 0) counter++;

    }
free(newa);
return x;
}

/*
 * NAME:        ~NetSnmpAgent.
 * PURPOSE:     Shuts down the snmp application, appropriate clean up.
 * PARAMETERS:  void.
 */

NetSnmpAgent::~NetSnmpAgent()
{
    snmp_close_sessions();
    shutdown_mib();
    unregister_all_config_handlers();
    netsnmp_container_free_list();
    clear_sec_mod();
    clear_snmp_enum();
    clear_callback();
    netsnmp_ds_shutdown();
    clear_user_list();
    netsnmp_clear_default_target();
    netsnmp_clear_default_domain();
    free_etimelist();

    init_snmp_init_done  = 0;
    _init_snmp_init_done = 0;

    netsnmp_context_subtree_free();
    clear_lookup_cache();
    netsnmp_clear_handler_list();
    SNMP_FREE(engineID);
}


