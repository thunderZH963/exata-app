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



#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
// This file is glue between OpenSSL and windows.
// In OpenSSL its location is $OPENSSL_HOME/ms/applink.c,
// which is renamed to applink.h
#include "applink.h"
#endif

// API
#include "main.h"
#include "api.h"
#include "partition.h"
#include "network_pki.h"

#include "mac.h"
#include "qualnet_error.h"

#include <vector>

#include "network_ip.h"

#ifdef _WIN32
#include<windows.h>
#else
#include<time.h>
#endif
using namespace std;
#ifdef JNE_LIB
#include "jne.h"
#include "jne_pki_data.h"
#endif

// Comment following line to close debug
//#define PKI_OPENSSL_DEBUG


// /**
// API        :: PKIGet__
// LAYER      :: Network
// PURPOSE    :: Following are Get methods for struct X509CertificateDetails
// **/

string
X509CertificateDetails::PKIGetPassphrase()
{
    return this->passphrase;
}

string
X509CertificateDetails::PKIGetCertificateFileName()
{
    return this->certificateFileName;
}

string
X509CertificateDetails::PKIGetPrivateKeyFileName()
{
    return this->privateKeyFileName;
}

X509*
X509CertificateDetails::PKIGetCertificate()
{
    return this->certificate;
}

EVP_PKEY*
X509CertificateDetails::PKIGetPrivateKey()
{
    return this->privateKey;
}

PrivateKeyType
X509CertificateDetails::PKIGetPrivateKeytype()
{
    return this->privateKeyType;
}

string
X509CertificateDetails::PKIGetSubjectCountryName()
{
    return this->subjectCountryName;
}

string
X509CertificateDetails::PKIGetSubjectStateName()
{
    return this->subjectStateName;
}

string
X509CertificateDetails::PKIGetSubjectLocation()
{
    return this->subjectLocation;
}

string
X509CertificateDetails::PKIGetSubjectOrganizationName()
{
    return this->subjectOrganizationName;
}

string
X509CertificateDetails::PKIGetSubjectOrganizationUnit()
{
    return this->subjectOrganizationUnit;
}

string
X509CertificateDetails::PKIGetSubjectCommonName()
{
    return this->subjectCommonName;
}

string
X509CertificateDetails::PKIGetSubjectEmail()
{
    return this->subjectEmail;
}

string
X509CertificateDetails::PKIGetSubjectDistinguishName()
{
    return this->subjectDistinguishName;
}

string
X509CertificateDetails::PKIGetIssuerCountryName()
{
    return this->issuerCountryName;
}

string
X509CertificateDetails::PKIGetIssuerStateName()
{
    return this->issuerStateName;
}

string
X509CertificateDetails::PKIGetIssuerLocation()
{
    return this->issuerLocation;
}

string
X509CertificateDetails::PKIGetIssuerOrganizationName()
{
    return this->issuerOrganizationName;
}

string
X509CertificateDetails::PKIGetIssuerOrganizationUnit()
{
    return this->issuerOrganizationUnit;
}

string
X509CertificateDetails::PKIGetIssuerCommonName()
{
    return this->issuerCommonName;
}

string
X509CertificateDetails::PKIGetIssuerEmail()
{
    return this->issuerEmail;
}

// /**
// API        :: PKISet__
// LAYER      :: Network
// PURPOSE    :: Following are Set methods for struct X509CertificateDetails
// **/

void
X509CertificateDetails::PKISetPassphrase(const char* pass)
{
    this->passphrase = pass;
}

void
X509CertificateDetails::PKISetCertificateFileName(const char* fileName)
{
    this->certificateFileName = fileName;
}

void
X509CertificateDetails::PKISetPrivateKeyFileName(const char* fileName)
{
    this->privateKeyFileName = fileName;
}

void
X509CertificateDetails::PKISetPrivateKey(EVP_PKEY* pKey)
{
    this->privateKey = pKey;
}


void
X509CertificateDetails::PKISetPrivateKeyType(PrivateKeyType keyType)
{
    this->privateKeyType = keyType;
}

void
X509CertificateDetails::PKISetCertificate(X509* certificate)
{
    this->certificate = certificate;
}


void
X509CertificateDetails::PKISetSubjectCountryName(const char* cnName)
{
    this->subjectCountryName = cnName;
}

void
X509CertificateDetails::PKISetSubjectStateName(const char* cnName)
{
    this->subjectStateName = cnName;
}

void
X509CertificateDetails::PKISetSubjectLocation(const char* cnName)
{
    this->subjectLocation = cnName;
}

void
X509CertificateDetails::PKISetSubjectOrganizationName(const char* cnName)
{
    this->subjectOrganizationName = cnName;
}

void
X509CertificateDetails::PKISetSubjectOrganizationUnit(const char* cnName)
{
    this->subjectOrganizationUnit = cnName;
}

void
X509CertificateDetails::PKISetSubjectCommonName(const char* cnName)
{
    this->subjectCommonName = cnName;
}

void
X509CertificateDetails::PKISetSubjectEmail(const char* cnName)
{
    this->subjectEmail = cnName;
}

void
X509CertificateDetails::PKISetSubjectDistinguishName(const char* distName)
{
    if (distName == NULL)
    {
        string defaultDistName;
        defaultDistName = "/C=" + this->PKIGetSubjectCountryName();
        defaultDistName += ("/ST=" + this->PKIGetSubjectStateName());
        defaultDistName += ("/LA=" + this->PKIGetSubjectLocation());
        defaultDistName += ("/O=" + this->PKIGetSubjectOrganizationName());
        defaultDistName += ("/OU=" + this->PKIGetSubjectOrganizationUnit());
        defaultDistName += ("/CN=" + this->PKIGetSubjectCommonName());
        defaultDistName += ("/emailAddress=" + this->PKIGetSubjectEmail());
        this->subjectDistinguishName = defaultDistName;
    }
    else
    {
        this->subjectDistinguishName = distName;
    }
}

void
X509CertificateDetails::PKISetIssuerCountryName(const char* cnName)
{
    this->issuerCountryName = cnName;
}

void
X509CertificateDetails::PKISetIssuerStateName(const char* cnName)
{
    this->issuerStateName = cnName;
}

void
X509CertificateDetails::PKISetIssuerLocation(const char* cnName)
{
    this->issuerLocation = cnName;
}

void
X509CertificateDetails::PKISetIssuerOrganizationName(const char* cnName)
{
    this->issuerOrganizationName = cnName;
}

void
X509CertificateDetails::PKISetIssuerOrganizationUnit(const char* cnName)
{
    this->issuerOrganizationUnit = cnName;
}

void
X509CertificateDetails::PKISetIssuerCommonName(const char* cnName)
{
    this->issuerCommonName = cnName;
}

void
X509CertificateDetails::PKISetIssuerEmail(const char* cnName)
{
    this->issuerEmail = cnName;
}

// /**
// API        :: X509CertificateInit
// LAYER      :: Network
// PURPOSE    :: To initialize the certificate.
// PARAMETERS ::
// + nodeId:  NodeId : owner node of certificate
// + instanceIndex :  int : certificate instance
// RETURN     :: void
// **/
void
X509CertificateDetails::X509CertificateInit(
    NodeId nodeId,
    int instanceIndex)
{
    char strValue[MAX_STRING_LENGTH] = {};

    this->PKISetSubjectCountryName("US");

    sprintf(strValue, "LA_%d", nodeId);
    this->PKISetSubjectLocation(strValue);

    sprintf(strValue, "CA_%d", nodeId);
    this->PKISetSubjectStateName(strValue);

    sprintf(strValue, "SNT_%d", nodeId);
    this->PKISetSubjectOrganizationName(strValue);

    sprintf(strValue, "EXata_%d", nodeId);
    this->PKISetSubjectOrganizationUnit(strValue);

    sprintf(strValue, "QualNet_%d_%d", nodeId, instanceIndex);
    this->PKISetSubjectCommonName(strValue);

    this->PKISetSubjectEmail("support@scalalable-networks.com");


    this->PKISetIssuerCountryName("US");

    sprintf(strValue, "LA_%d", nodeId);
    this->PKISetIssuerLocation(strValue);

    sprintf(strValue, "CA_%d", nodeId);
    this->PKISetIssuerStateName(strValue);

    sprintf(strValue, "SNT_%d", nodeId);
    this->PKISetIssuerOrganizationName(strValue);

    sprintf(strValue, "EXata_%d", nodeId);
    this->PKISetIssuerOrganizationUnit(strValue);

    sprintf(strValue, "QualNet_%d_%d", nodeId, instanceIndex);
    this->PKISetIssuerCommonName(strValue);

    this->PKISetIssuerEmail("support@scalalable-networks.com");


    sprintf(strValue, "certificate.%d.%d.pem", nodeId, instanceIndex);
    this->PKISetCertificateFileName(strValue);


    sprintf(strValue, "privateKey.%d.%d.pem", nodeId, instanceIndex);
    this->PKISetPrivateKeyFileName(strValue);


    this->PKISetPrivateKeyType(RSA_KEY);
    this->PKISetPassphrase("");
}

// /**
// API        :: PKIReadSubjectConfiguration
// LAYER      :: Network
// PURPOSE    :: To read certificate's subject configuration.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + nodeInput:  const NodeInput* : PKI configured file
// + nodeId:  NodeId : owner node of certificate
// + instanceIndex :  int : certificate instance
// RETURN     :: void
// **/
void
X509CertificateDetails::PKIReadSubjectConfiguration(
    Node* node,
    const NodeInput* nodeInput,
    NodeId nodeId,
    int instanceIndex)
{
    BOOL found = FALSE;
    char value[MAX_STRING_LENGTH] = {};

    int interfaceIndex = 0; // Change this

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-COUNTRYNAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectCountryName(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-STATENAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectStateName(value);
    }

     IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-LOCATION",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectLocation(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-ORGNAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectOrganizationName(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-ORGUNIT",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectOrganizationUnit(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-COMMONNAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectCommonName(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-OWNER-EMAIL",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetSubjectEmail(value);
    }
    this->PKISetSubjectDistinguishName(NULL);
}


// /**
// API        :: PKIReadIssuerConfiguration
// LAYER      :: Network
// PURPOSE    :: To read certificate's issuer configuration.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + nodeInput:  const NodeInput* : PKI configured file
// + nodeId:  NodeId : owner node of certificate
// + instanceIndex :  int : certificate instance
// RETURN     :: void
// **/
void
X509CertificateDetails::PKIReadIssuerConfiguration(
    Node* node,
    const NodeInput* nodeInput,
    NodeId nodeId,
    int instanceIndex)
{
    BOOL found = FALSE;
    char value[MAX_STRING_LENGTH] = {};

    int interfaceIndex = 0;

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-COUNTRYNAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerCountryName(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-STATENAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerStateName(value);
    }

     IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-LOCATION",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerLocation(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-ORGNAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerOrganizationName(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-ORGUNIT",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerOrganizationUnit(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-COMMONNAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerCommonName(value);
    }

    IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "CERTIFICATE-ISSUER-EMAIL",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetIssuerEmail(value);
    }
}


// /**
// API        :: PKICallbackForRsaGenerateKey
// LAYER      :: Network
// PURPOSE    :: Callback function for OpenSSL method RSA_generate_key.
// PARAMETERS ::
// + p:  int :
// + n:  int :
// + arg:  void* :
// RETURN     :: void
// **/
static
void PKICallbackForRsaGenerateKey(int p, int n, void* arg)
{
    char c = 'B';

    if (p == 0)
    {
        c = '.';
    }
    if (p == 1)
    {
        c = '+';
    }
    if (p == 2)
    {
        c = '*';
    }
    if (p == 3)
    {
        c = '\n';
    }
    fputc(c, stderr);
}


// /**
// API        :: PKIReadPrivateKeyConfiguration
// LAYER      :: Network
// PURPOSE    :: To read private key configuration.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + nodeInput:  const NodeInput* : PKI configured file
// + nodeId:  NodeId : owner node of certificate
// + instanceIndex :  int : certificate instance
// RETURN     :: void
// **/
void
X509CertificateDetails::PKIReadPrivateKeyConfiguration(
    Node* node,
    const NodeInput* nodeInput,
    NodeId nodeId,
    int instanceIndex,
    bool wantNewKey = false)
{
    int interfaceIndex = 0;
    BOOL found = FALSE;
    BOOL checkKeyType = TRUE;
    char value[MAX_STRING_LENGTH] = {};
    char passValue[MAX_STRING_LENGTH] = "";
    BOOL passFound = FALSE;

    if (wantNewKey == FALSE)
    {
        IO_ReadStringInstance(
                node,
                nodeId,
                interfaceIndex,
                nodeInput,
                "PRECONFIGURED-PRIVATE-KEY-FILE",
                instanceIndex,
                TRUE,
                &found,
                value);
        // read the pass phrase
        IO_ReadStringInstance(
            nodeId,
            ANY_ADDRESS,
            nodeInput,
            "PRECONFIGURED-CERTIFICATE-PASSPHRASE",
            instanceIndex,
            TRUE,
            &passFound,
            passValue);

        if (found)
        {
            EVP_PKEY* privateKey = EVP_PKEY_new();
            FILE* keyFile = fopen(value, "r");
            if (keyFile != NULL)
            {
                if (passFound)
                {
                    privateKey = PEM_read_PrivateKey(keyFile,
                                                     NULL,
                                                     NULL,
                                                     passValue);
                    this->PKISetPassphrase(passValue);

                }
                else
                {
                    privateKey = PEM_read_PrivateKey(keyFile,
                                                     NULL,
                                                     NULL,
                                                     NULL);
                }
                if (!privateKey)
                {
                    char ebuf[256] = {};
                    sprintf(ebuf, "Configured passphrase does not match"
                        " the one using which key was generated");
                    ERROR_ReportError(ebuf);
                }
                this->PKISetPrivateKey(privateKey);
                this->PKISetPrivateKeyFileName(value);
                RSA* rsa = NULL;
                DSA* dsa = NULL;
                rsa = EVP_PKEY_get1_RSA(privateKey);
                if (rsa)
                {
                    this->PKISetPrivateKeyType(RSA_KEY);
                    checkKeyType = FALSE;
                }
                dsa = EVP_PKEY_get1_DSA(privateKey);
                if (dsa)
                {
                    this->PKISetPrivateKeyType(DSA_KEY);
                    checkKeyType = FALSE;
                }
            }
            fclose(keyFile);
        }
        else
        {
            char ebuf[256] = {};
            sprintf(ebuf, "For Node %d Cert Index %d "
                "PRECONFIGURED-PRIVATE-KEY-FILE is required\n",
                node->nodeId, instanceIndex);
            ERROR_ReportError(ebuf);
        }
    }

    if (wantNewKey && checkKeyType)
    {
        FILE* keyFile = NULL;
        EVP_PKEY* privateKey = EVP_PKEY_new();
        int status = -1;

        IO_ReadStringInstance(
            node,
            nodeId,
            interfaceIndex,
            nodeInput,
            "PRIVATE-KEY-TYPE",
            instanceIndex,
            TRUE,
            &found,
            value);
        // read the pass phrase
        IO_ReadStringInstance(
            nodeId,
            ANY_ADDRESS,
            nodeInput,
            "GENERATED-CERTIFICATE-PASSPHRASE",
            instanceIndex,
            TRUE,
            &passFound,
            passValue);
        if (found)
        {
            if (strcmp(value, "DSA") == 0)
            {
                this->PKISetPrivateKeyType(DSA_KEY);
                BOOL dsaGenerated = FALSE;
                DSA* dsa = NULL;
                dsa = DSA_generate_parameters(512,
                                              NULL,
                                              0,
                                              NULL,
                                              NULL,
                                              NULL,
                                              NULL);
                dsaGenerated = DSA_generate_key(dsa);

                if (dsaGenerated)
                {
                    EVP_PKEY_assign_DSA(privateKey, dsa);
                }
            }
            else if (strcmp(value, "RSA") == 0)
            {
                this->PKISetPrivateKeyType(RSA_KEY);
                RSA* rsa;
                rsa = RSA_generate_key(PKI_RSA_KEY_LENGTH,
                                       RSA_F4,
                                       PKICallbackForRsaGenerateKey,
                                       NULL);
                EVP_PKEY_assign_RSA(privateKey, rsa);
            }
            else
            {
                ERROR_ReportError("Specify valid PRIVATE-KEY-TYPE");
            }
        }
        else
        {
            this->PKISetPrivateKeyType(RSA_KEY);
            RSA* rsa;
            rsa = RSA_generate_key(PKI_RSA_KEY_LENGTH,
                                   RSA_F4,
                                   PKICallbackForRsaGenerateKey,
                                   NULL);
            EVP_PKEY_assign_RSA(privateKey, rsa);
        }

        keyFile = fopen(this->PKIGetPrivateKeyFileName().c_str(), "w");
        if (keyFile == NULL)
        {
            fclose(keyFile);
            ERROR_ReportError(
                "Cannot open Private Key File for writing\n");
        }
        if (!passFound)
        {
            status = PEM_write_PrivateKey(keyFile,
                                          privateKey,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL,
                                          NULL);
        }
        else
        {
            status = PEM_write_PrivateKey(keyFile,
                                          privateKey,
                                          EVP_des_ede3_cbc(),
                                          NULL,
                                          0,
                                          NULL,
                                          passValue);
            this->PKISetPassphrase(passValue);
        }
        if (!status)
        {
            char errbuf[256] = {};
            ERR_error_string(ERR_get_error(), errbuf);
            ERROR_ReportError(errbuf);
        }
        else
        {
            this->PKISetPrivateKey(privateKey);
        }
        fclose(keyFile);
    }
}

// /**
// API        :: PKIReadCertificateFileName
// LAYER      :: Network
// PURPOSE    :: To read configured certificate file name.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + nodeInput:  const NodeInput* : PKI configured file
// + nodeId:  NodeId : owner node of certificate
// + instanceIndex :  int : certificate instance
// RETURN     :: void
// **/
void
X509CertificateDetails::PKIReadCertificateFileName(
    Node* node,
    const NodeInput* nodeInput,
    NodeId nodeId,
    int instanceIndex)
{
    BOOL found = FALSE;
    char value[MAX_STRING_LENGTH] = {};

    IO_ReadStringInstance(
            nodeId,
            ANY_ADDRESS,
            nodeInput,
            "CERTIFICATE-FILENAME",
            instanceIndex,
            TRUE,
            &found,
            value);
    if (found)
    {
        this->PKISetCertificateFileName(value);
    }
}


// /**
// API        :: X509CertificateSubjectIssuerDetail
// LAYER      :: Network
// PURPOSE    :: To get information of subject or issuer.
// PARAMETERS ::
// + nameDetail:  X509_NAME* : certificate's subject or issuer pointer
// + certificate:  X509* : certificate pointer
// + fileName:  char* : certificate file name
// + detailsOption :  BOOL : whose information needed i.e subject or issuer
// + field :  int : which field i.e. name, countary, E-mail, etc.
// + length :  int* : length of returned field
// RETURN     :: char* : field value
// **/
char*
X509CertificateSubjectIssuerDetail(
    X509_NAME* nameDetail,
    X509* certificate,
    char* fileName,
    BOOL detailsOption,
    int field,
    int* length)
{
    int index = -1;
    BOOL isFile = FALSE;
    X509_NAME* subject = NULL;
    X509_NAME_ENTRY* e = NULL;
    char* fieldValue;

    if (nameDetail == NULL)
    {
        if (certificate == NULL)
        {
            if (fileName != NULL)
            {
                FILE* certFile = fopen(fileName, "r");
                if (certFile == NULL)
                {
                    fclose(certFile);
                    *length = 0;
                    return NULL;
                }
                isFile = TRUE;
                certificate = PEM_read_X509(certFile, NULL, NULL, NULL);
                fclose(certFile);
            }
            else
            {
                *length = 0;
                return NULL;
            }
        }

        if (detailsOption == SUBJECT_DETAIL)
        {
            subject = X509_get_subject_name(certificate);
        }
        else if (detailsOption == ISSUER_DETAIL)
        {
            subject = X509_get_issuer_name(certificate);
        }
    }
    else
    {
        subject = nameDetail;
    }


    index = X509_NAME_get_index_by_NID(subject, field, index);
    e = X509_NAME_get_entry(subject, index);

    *length = e->value->length;

    fieldValue = (char*) MEM_malloc(*length + 1);
    memset(fieldValue, '\0', *length + 1);
    memcpy(fieldValue, e->value->data, *length);

    if (isFile)
    {
        X509_free(certificate);
    }

    return fieldValue;
}


// /**
// API        :: PKIParseCertificateFile
// LAYER      :: Network
// PURPOSE    :: To get certificate information from certificate file
// PARAMETERS ::
// + fileName:  char* : certificate filename
// RETURN     :: void
// **/
void
X509CertificateDetails::PKIParseCertificateFile(
    X509* cert)
{
    X509_NAME* subject = NULL;
    X509_NAME* issuer = NULL;
    X509_NAME_ENTRY* e = NULL;
    int index = -1;
#ifdef PKI_OPENSSL_DEBUG
    char errbuf[256] = {};
#endif

    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);


    index = X509_NAME_get_index_by_NID(subject, NID_commonName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(subject, index);
    if (e != NULL)
    {
        this->PKISetSubjectCommonName((const char*)e->value->data);
    }

    index = X509_NAME_get_index_by_NID(subject, NID_countryName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }

    e = X509_NAME_get_entry(subject, index);
    if (e != NULL)
    {
        this->PKISetSubjectCountryName((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(subject, NID_localityName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(subject, index);

    if (e != NULL)
    {
        this->PKISetSubjectLocation((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(subject,
                                        NID_stateOrProvinceName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(subject, index);
    if (e != NULL)
    {
        this->PKISetSubjectStateName((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(subject, NID_organizationName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(subject, index);
    if (e != NULL)
    {
        this->PKISetSubjectOrganizationName((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(subject,
                                        NID_organizationalUnitName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(subject, index);
    if (e != NULL)
    {
        this->PKISetSubjectOrganizationUnit((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(subject,
                                        NID_pkcs9_emailAddress, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(subject, index);
    if (e != NULL)
    {
        this->PKISetSubjectEmail((const char*)e->value->data);
    }

        // parsing issuer details
    index = X509_NAME_get_index_by_NID(issuer, NID_commonName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(issuer, index);
    if (e != NULL)
    {
        this->PKISetIssuerCommonName((const char*)e->value->data);
    }

    index = X509_NAME_get_index_by_NID(issuer, NID_countryName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }

    e = X509_NAME_get_entry(issuer, index);
    if (e != NULL)
    {
        this->PKISetIssuerCountryName((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(issuer, NID_localityName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(issuer, index);

    if (e != NULL)
    {
        this->PKISetIssuerLocation((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(issuer,
                                        NID_stateOrProvinceName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(issuer, index);
    if (e != NULL)
    {
        this->PKISetIssuerStateName((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(issuer, NID_organizationName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(issuer, index);
    if (e != NULL)
    {
        this->PKISetIssuerOrganizationName((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(issuer,
                                        NID_organizationalUnitName, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }

    e = X509_NAME_get_entry(issuer, index);
    if (e != NULL)
    {
        this->PKISetIssuerOrganizationUnit((const char*)e->value->data);
    }


    index = X509_NAME_get_index_by_NID(issuer,
                                        NID_pkcs9_emailAddress, index);
    if (index == -1)
    {
#ifdef PKI_OPENSSL_DEBUG
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
#endif
    }
    e = X509_NAME_get_entry(issuer, index);
    if (e != NULL)
    {
        this->PKISetIssuerEmail((const char*)e->value->data);
    }
}

// /**
// API        :: PKIAddCertExtension
// LAYER      :: Network
// PURPOSE    :: To add X509 certificate extensions
// PARAMETERS ::
// + cert:  X509* : X509 certificate
// + nid:  int : index in certificate to add value to.
// + value:  char* : value to insert
// RETURN     :: int : 1 if successful.0 otherwise
// **/
int
PKIAddCertExtension(X509* cert, int nid, char* value)
{
    X509_EXTENSION* ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
     * no request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
    {
        return 0;
    }
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}



// /**
// API        :: PKIGenerateCertificate
// LAYER      :: Network
// PURPOSE    :: To generate encrypted certificate file from
//               certificate information
// PARAMETERS ::
// RETURN     :: BOOL : TRUE if certificate is generated
// **/
BOOL
X509CertificateDetails::PKIGenerateCertificate()
{
    X509* cert;
    X509_NAME* subject;
    X509_NAME* issuer;
    FILE* fp = NULL;
    EVP_PKEY* privateKey;
    long int serial = 0;
    char errbuf[256] = {};
    char PKIerrbuf[256] = {};
    int status = -1;

    string subCountryName;
    string subLocation;
    string subStateName;
    string subOrgName;
    string subOrgUnit;
    string subCommonName;
    string subEmail;
    string issCountryName;
    string issLocation;
    string issStateName;
    string issOrgName;
    string issOrgUnit;
    string issCommonName;
    string issEmail;

    string pKeyFileName;


    if (!(cert = X509_new()))
    {
        return FALSE;
    }

    if (!(subject = X509_NAME_new()))
    {
        return FALSE;
    }

    // Set version number and serial number
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);

    // Set validity time
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)365*24*60*60);

    // set public key in certificate, read from privateKeyFile
    pKeyFileName = this->PKIGetPrivateKeyFileName();

    FILE* keyFile = fopen(pKeyFileName.c_str(), "r");
    if (keyFile == NULL)
    {
        fclose(keyFile);
        ERROR_ReportError(
           "Cannot read Private Key File\n");
    }
    privateKey = PEM_read_PrivateKey(keyFile, NULL, NULL, (void*) (this->PKIGetPassphrase().c_str()));
    fclose(keyFile);
    if (privateKey == NULL)
    {
        ERROR_ReportError(
           "Unrecognised Private Key File\n");
    }
    // Set Public key
    X509_set_pubkey(cert, privateKey);

    subCountryName = this->PKIGetSubjectCountryName();
    subLocation = this->PKIGetSubjectLocation();
    subStateName = this->PKIGetSubjectStateName();
    subOrgName = this->PKIGetSubjectOrganizationName();
    subOrgUnit = this->PKIGetSubjectOrganizationUnit();
    subCommonName = this->PKIGetSubjectCommonName();
    subEmail = this->PKIGetSubjectEmail();

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_COMMON_NAME,
                    MBSTRING_ASC,
                    (const unsigned char*)subCommonName.c_str(),
                    subCommonName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject Common Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_COUNTRY,
                    MBSTRING_ASC,
                    (unsigned char*)subCountryName.c_str(),
                    subCountryName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject Country Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_LOCATION,
                    MBSTRING_ASC,
                    (const unsigned char*)subLocation.c_str(),
                    subLocation.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject Location)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_STATE,
                    MBSTRING_ASC,
                    (const unsigned char*)subStateName.c_str(),
                    subStateName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject State Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_ORGANIZATION,
                    MBSTRING_ASC,
                    (const unsigned char*)subOrgName.c_str(),
                    subOrgName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject Org Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_ORG_UNIT,
                    MBSTRING_ASC,
                    (const unsigned char*)subOrgUnit.c_str(),
                    subOrgUnit.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject Org Unit)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    subject,
                    PKI_EMAIL_ADDR,
                    MBSTRING_ASC,
                    (const unsigned char*)subEmail.c_str(),
                    subEmail.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Subject Email Address)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    if (X509_set_subject_name(cert, subject) != 1)
    {
        return FALSE;
    }


    if (!(issuer = X509_NAME_new()))
    {
        return FALSE;
    }

    issCountryName = this->PKIGetIssuerCountryName();
    issLocation = this->PKIGetIssuerLocation();
    issStateName = this->PKIGetIssuerStateName();
    issOrgName = this->PKIGetIssuerOrganizationName();
    issOrgUnit = this->PKIGetIssuerOrganizationUnit();
    issCommonName = this->PKIGetIssuerCommonName();
    issEmail = this->PKIGetIssuerEmail();

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_COMMON_NAME,
                    MBSTRING_ASC,
                    (const unsigned char*)issCommonName.c_str(),
                    issCommonName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer Common Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_COUNTRY,
                    MBSTRING_ASC,
                    (const unsigned char*)issCountryName.c_str(),
                    issCountryName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer Country Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_LOCATION,
                    MBSTRING_ASC,
                    (const unsigned char*)issLocation.c_str(),
                    issLocation.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer Location)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_STATE,
                    MBSTRING_ASC,
                    (const unsigned char*)issStateName.c_str(),
                    issStateName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer State Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_ORGANIZATION,
                    MBSTRING_ASC,
                    (const unsigned char*)issOrgName.c_str(),
                    issOrgName.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer Org Name)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_ORG_UNIT,
                    MBSTRING_ASC,
                    (const unsigned char*)issOrgUnit.c_str(),
                    issOrgUnit.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer Org Unit)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    status = X509_NAME_add_entry_by_txt(
                    issuer,
                    PKI_EMAIL_ADDR,
                    MBSTRING_ASC,
                    (const unsigned char*)issEmail.c_str(),
                    issEmail.size(),
                    -1,
                    0);
    if (status == 0)
    {
        ERR_error_string(ERR_get_error(), errbuf);
        sprintf(PKIerrbuf,
            "PKI-ERROR(Check Configuration for Issuer Email Address)"
            "\nOPENSSL-ERROR(%s)\n",errbuf);
        ERROR_ReportError(PKIerrbuf);
    }

    if (X509_set_issuer_name(cert, issuer) != 1)
    {
        return FALSE;
    }


    /* Add various extensions: standard extensions */
    PKIAddCertExtension(cert,
                        NID_basic_constraints,
                        (char*)Extension_For_Basic_Constraints);
    PKIAddCertExtension(cert,
                        NID_key_usage,
                        (char*)Extension_For_Key_Usage);
    PKIAddCertExtension(cert,
                        NID_subject_key_identifier,
                        (char*)Extension_For_Subject_Key_Identifier);
    /* Some Netscape specific extensions */
    PKIAddCertExtension(cert,
                        NID_netscape_cert_type,
                        (char*)Extension_For_Netscape_Cert_Type);
    PKIAddCertExtension(cert,
                        NID_netscape_comment,
                        (char*)Extension_For_Netscape_Comment);

#ifdef CUSTOM_EXT
    /* Maybe even add our own extension based on existing */
    {
        int nid;
        nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        PKIAddCertExtension(cert, nid, (char*)"example comment alias");
    }
#endif

    EVP_MD* digest = (EVP_MD*) EVP_sha1();
    if (!(X509_sign(cert, privateKey, digest)))
    {
        return FALSE;
    }

    fp = fopen(this->PKIGetCertificateFileName().c_str(), "w");
    if (fp == NULL)
    {
        fclose(fp);
        return FALSE;
    }

    X509_print_fp(fp, cert);
    this->PKISetCertificate(cert);
    if (PEM_write_X509(fp, cert) != 1)
    {
        fclose(fp);
        return FALSE;
    }

    fclose(fp);
    EVP_PKEY_free(privateKey);

    return TRUE;
}


// /**
// API        :: PkiExtractValidityInfo
// LAYER      :: Network
// PURPOSE    :: To return the integer data read from the certificate 
//               validity data
// PARAMETERS :: unsigned char* : the certificate validity data
//............:: char* : flag specifying what type of data to read 
//                       and convert
// RETURN     :: int : the integral value of the certificate validity data
// **/
static
int PkiExtractValidityInfo(unsigned char* certValidData,
                           ValidityInfoType info)
{
    int retValue = 0;
    int a =0;
    int b =0;

    switch(info)
    {
        case PKI_YEAR:
            a = certValidData[0] - 48;
            b = certValidData[1] - 48;
            retValue = 2000 + a * 10 + b;
            break;
        case PKI_MONTH:
            a = certValidData[2] - 48;
            b = certValidData[3] - 48;
            retValue = a * 10 + b;
            break;
        case PKI_DAY:
            a = certValidData[4] - 48;
            b= certValidData[5] - 48;
            retValue = a * 10 + b;
            break;
        case PKI_HOUR:
            a = certValidData[6] - 48;
            b = certValidData[7] - 48;
            retValue = a * 10 + b;
            break;
        case PKI_MIN:
            a = certValidData[8] - 48;
            b = certValidData[9] - 48;
            retValue = a * 10 + b;
            break;
        case PKI_SEC:
            a = certValidData[10] - 48;
            b =  certValidData[11] - 48;
            retValue = a * 10 + b;
            break;
        default:
            break;
    }
    return retValue;
}


// /**
// API        :: PKICheckValidityforAfter
// LAYER      :: Network
// PURPOSE    :: To check certificate's notValidAfter validity
// PARAMETERS :: ASN1_TIME* : Certificate's notAfter validity data
// RETURN     :: bool : returns true if valid,false if otherwise
// **/
static
bool PKICheckValidityforAfter(ASN1_TIME* notAfter)
{

#ifdef _WIN32 //for windows
    SYSTEMTIME st;
    GetSystemTime(&st);
    unsigned char* certValidData = notAfter->data;
    if (st.wYear < PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return true;
    }
    if (st.wYear > PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return false;
    }
    if (st.wMonth < PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return true;
    }
    if (st.wMonth > PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return false;
    }
    if (st.wDay < PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return true;
    }
    if (st.wDay > PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return false;
    }
    if (st.wHour < PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return true;
    }
    if (st.wHour > PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return false;
    }
    if (st.wMinute < PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return true;
    }
    if (st.wMinute > PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return false;
    }
    if (st.wSecond < PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return true;
    }
    if (st.wSecond > PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return false;
    }

    return true;

#else  // for linux/unix 

    time_t now;
    struct tm t;
    now = time(NULL);
    gmtime_r(&now , &t);
    unsigned char* certValidData = notAfter->data;
    if ((t.tm_year + 1900) < PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return true;
    }
    if ((t.tm_year + 1900) > PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return false;
    }
    if ((t.tm_mon + 1) < PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return true;
    }
    if ((t.tm_mon + 1) > PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return false;
    }
    if (t.tm_mday < PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return true;
    }
    if (t.tm_mday > PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return false;
    }
    if (t.tm_hour < PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return true;
    }
    if (t.tm_hour > PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return false;
    }
    if (t.tm_min < PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return true;
    }
    if (t.tm_min > PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return false;
    }
    if (t.tm_sec < PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return true;
    }
    if (t.tm_sec > PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return false;
    }

    return true;

#endif

}

// /**
// API        :: PKICheckValidityforBefore
// LAYER      :: Network
// PURPOSE    :: To check certificate's notValidBefore validity
// PARAMETERS :: ASN1_TIME* : Certificate's notBefore validity data
// RETURN     :: bool : returns true if valid,false if otherwise
// **/
static
bool PKICheckValidityforBefore(ASN1_TIME* notBefore)
{

#ifdef _WIN32 // for windows
    SYSTEMTIME st;
    GetSystemTime(&st);
    unsigned char* certValidData = notBefore->data;

    if (st.wYear > PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return true;
    }
    if (st.wYear < PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return false;
    }
    if (st.wMonth > PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return true;
    }
    if (st.wMonth < PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return false;
    }
    if (st.wDay > PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return true;
    }
    if (st.wDay < PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return false;
    }
    if (st.wHour > PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return true;
    }
    if (st.wHour < PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return false;
    }
    if (st.wMinute > PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return true;
    }
    if (st.wMinute < PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return false;
    }
    if (st.wSecond > PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return true;
    }
    if (st.wSecond < PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return false;
    }

    return true;

#else
    time_t now;
    struct tm t;
    now = time(NULL);
    gmtime_r(&now , &t);
    unsigned char* certValidData = notBefore->data;

    if ((t.tm_year + 1900) > PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return true;
    }
    if ((t.tm_year + 1900) < PkiExtractValidityInfo(certValidData, PKI_YEAR)) {
        return false;
    }
    if ((t.tm_mon + 1) > PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return true;
    }
    if ((t.tm_mon+1) < PkiExtractValidityInfo(certValidData, PKI_MONTH)) {
        return false;
    }
    if (t.tm_mday > PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return true;
    }
    if (t.tm_mday < PkiExtractValidityInfo(certValidData, PKI_DAY)) {
        return false;
    }
    if (t.tm_hour > PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return true;
    }
    if (t.tm_hour < PkiExtractValidityInfo(certValidData, PKI_HOUR)) {
        return false;
    }
    if (t.tm_min > PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return true;
    }
    if (t.tm_min < PkiExtractValidityInfo(certValidData, PKI_MIN)) {
        return false;
    }
    if (t.tm_sec > PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return true;
    }
    if (t.tm_sec < PkiExtractValidityInfo(certValidData, PKI_SEC)) {
        return false;
    }

    return true;
#endif
}


// /**
// API        :: PKIInsertCertificate
// LAYER      :: Network
// PURPOSE    :: To Insert certificate details in the
// ..............pkiData data structure
// PARAMETERS :: char[]: the name of the certificate filename
//                 X509 *: X509 certificate
//                 Node *: the Node pointer
//                 BOOL : whether the given certificate entry
//........................is of pem format or not
//                 NodeInput*:NodeInput pointer to read private key from
//                 int : the certificate index
//                 EVP_PKEY* : private key.Default value is NULL,
//                 BOOL :whether certificate is shared or not.
//                       Default False
// **/
void
PKIInsertCertificate(char value[],
                 X509* certx,
                 Node* node,
                 BOOL isPemFormat,
                 char* passValue,
                 NodeInput* pkiConfigurationInput,
                 int certIndex,
                 EVP_PKEY* pkey = NULL,
                 BOOL isSharedConfiguration = FALSE)
{
    NetworkData* nData = &node->networkData;
    PKIData* pkiData = nData->pkiData;
    map<string, X509CertificateDetails*>::iterator it;
    int length;
    char* commonName = X509CertificateSubjectIssuerDetail(
                        NULL,
                        certx,
                        NULL,
                        SUBJECT_DETAIL,
                        NID_commonName,
                        &length);
    if (commonName == NULL)
    {
        return;
    }

    X509CertificateDetails* certDetail;
    string commonNameStr = commonName;

    bool isvalidAfter =
        PKICheckValidityforAfter(certx->cert_info->validity->notAfter);
    bool isvalidBefore =
        PKICheckValidityforBefore(certx->cert_info->validity->notBefore);

    if (isvalidAfter == false || isvalidBefore == false)
    {
        char errbuf[200];
        sprintf(errbuf,"Validity Expired for Certificate at Node %d.\n",
            node->nodeId);
        ERROR_ReportWarning(errbuf);
        return;
    }

    if (isSharedConfiguration)
    {
        it = pkiData->sharedCertificate->find(commonNameStr);
        if (it == pkiData->sharedCertificate->end())
        {
            certDetail = new X509CertificateDetails;
            certDetail->PKISetCertificate(certx);
            certDetail->PKISetCertificateFileName(value);
            certDetail->PKIParseCertificateFile(certx);
            certDetail->PKISetPrivateKeyType(NO_KEY);
            pkiData->sharedCertificate->insert(
                    pair<string, X509CertificateDetails*>
                    (commonName, certDetail));
        }
        else
        {
            ERROR_ReportWarning("Cannont insert certificate with duplicate"
                " Owner-Common-Name.\n");
        }
    }
    else
    {
        it = pkiData->certificateList->find(commonNameStr);
        if (it == pkiData->certificateList->end())
        {
            certDetail = new X509CertificateDetails;
            certDetail->PKISetCertificate(certx);
            certDetail->PKISetCertificateFileName(value);
            certDetail->PKIParseCertificateFile(certx);
            // only self certificate cares the distinguish name
            certDetail->PKISetSubjectDistinguishName(certx->name);

            //Pem format
            if (isPemFormat)
            {
                certDetail->PKIReadPrivateKeyConfiguration(
                        node,
                        pkiConfigurationInput,
                        node->nodeId,
                        certIndex);
            }
            //P12 format
            else if (!isPemFormat && pkey != NULL)
            {
                certDetail->PKISetPrivateKey(pkey);
                certDetail->PKISetPrivateKeyFileName(value);
                // This case is used to populate the passphrase
                // in case of p12 format.
                if (passValue)
                {
                    certDetail->PKISetPassphrase(passValue);
                }
                RSA* rsa = NULL;
                DSA* dsa = NULL;
                rsa = EVP_PKEY_get1_RSA(pkey);
                if (rsa)
                {
                    certDetail->PKISetPrivateKeyType(RSA_KEY);
                }
                dsa = EVP_PKEY_get1_DSA(pkey);
                if (dsa)
                {
                    certDetail->PKISetPrivateKeyType(DSA_KEY);
                }
            }
            pkiData->certificateList->insert(
                        pair<string, X509CertificateDetails*>
                        (commonName, certDetail));
#ifdef JNE_LIB
        if (JNE_IsModuleEnabled(node, JNE_DATA_PKI))
        {
            JNE::PkiData& jnePkiData = JNE_GetModuleData<JNE::PkiData>(node, JNE_DATA_PKI);
            jnePkiData.parseJnePkiConfiguration(node, pkiConfigurationInput, certIndex, commonNameStr);
        }
#endif

        }
        else
        {
#ifdef JNE_LIB
        if (JNE_IsModuleEnabled(node, JNE_DATA_PKI))
        {
            JNE::PkiData& jnePkiData = JNE_GetModuleData<JNE::PkiData>(node, JNE_DATA_PKI);
            jnePkiData.parseJnePkiConfiguration(node, pkiConfigurationInput, certIndex, commonNameStr);
        }
#endif
      //      ERROR_ReportWarning("Cannont insert certificate with duplicate"
      //          " Owner-Common-Name.\n");
        }
    }
}


// /**
// API        :: PKIReadCertificateFileConfiguration
// LAYER      :: Network
// PURPOSE    :: To parse certificate file
// PARAMETERS ::
// + node    :  Node* : node that is parsing certificate file
// + pkiConfigurationInput  :  NodeInput* : PKI configured file
// + nodeId   :  NodeId : nodeId of the node
// RETURN     :: void
// **/
static
void PKIReadCertificateFileConfiguration(
    Node* node,
    NodeInput* pkiConfigurationInput,
    NodeId nodeId)
{
    int instanceIndex = 0;
    BOOL found = FALSE;
    char value[MAX_STRING_LENGTH * 2] = {};
    map<string, X509CertificateDetails*>::iterator it;
    BOOL isPemFormat = FALSE;
    int certCount=-1;

    IO_ReadInt(
        nodeId,
        ANY_ADDRESS,
        pkiConfigurationInput,
        "PRECONFIGURED-CERTIFICATE-PRIVATEKEY-PAIR-COUNT",
        &found,
        &certCount);

    if ((found) && (certCount <= 0))
    {
        ERROR_ReportError(
                    "PRECONFIGURED-CERTIFICATE-PRIVATEKEY-PAIR-COUNT"
                    " parameter require value greater than 0\n");
    }

    if (found)
    {
        while (instanceIndex < certCount)
        {
            IO_ReadStringInstance(
                    nodeId,
                    ANY_ADDRESS,
                    pkiConfigurationInput,
                    "PRECONFIGURED-CERTIFICATE-FILE-TYPE",
                    instanceIndex,
                    TRUE,
                    &found,
                    value);
            // file type parameter not found
            if (!found)
            {
                instanceIndex++;
                continue;
            }

            // file type found but unknown value
            if (found && strcmp(value, "PEM") != 0 &&
                strcmp(value, "P12") != 0)
            {
                ERROR_ReportError(
                     "PRECONFIGURED-CERTIFICATE-FILE-TYPE parameter can only"
                     " have value PEM/P12 \n");
            }

            // PEM FORMAT
            if (found && strcmp(value, "PEM") == 0)
            {
                IO_ReadStringInstance(
                        nodeId,
                        ANY_ADDRESS,
                        pkiConfigurationInput,
                        "PRECONFIGURED-CERTIFICATE-FILE",
                        instanceIndex,
                        TRUE,
                        &found,
                        value);

                if (!found)
                {
                    ERROR_ReportError(
                            "PRECONFIGURED-CERTIFICATE-FILE required "
                            "parameter not found \n");
                }
                else
                {
                    FILE* f = fopen(value, "r");
                    if (f == NULL)
                    {
                        fclose(f);
                        ERROR_ReportError(
                            "Cannot open Certificate File\n");
                    }
                    X509* certx = PEM_read_X509(f, NULL, NULL, NULL);
                    fclose(f);
                    isPemFormat = TRUE;
                    if (certx != NULL)
                    {
                        PKIInsertCertificate(value,
                            certx,
                            node,
                            isPemFormat,
                            NULL,
                            pkiConfigurationInput,
                            instanceIndex);
                    }
                    else
                    {
                        ERROR_ReportError(
                               "Could not read the PEM certificate file \n");
                    }
                }
            }
            //P12 format
            else if (found && strcmp(value,"P12") == 0)
            {
                IO_ReadStringInstance(
                        nodeId,
                        ANY_ADDRESS,
                        pkiConfigurationInput,
                        "PRECONFIGURED-CERTIFICATE-FILE",
                        instanceIndex,
                        TRUE,
                        &found,
                        value);

                if (!found)
                {
                    ERROR_ReportError(
                          "PRECONFIGURED-CERTIFICATE-FILE required parameter"
                          " not found \n");
                }
                else
                {
                    FILE* fp = fopen(value, "r");
                    if (fp == NULL)
                    {
                        fclose(fp);
                        ERROR_ReportError(
                            "Cannot Open Certificate File\n");
                    }
                    PKCS12* p12DS = NULL;
                    int result = 0;
                    EVP_PKEY* pkey;
                    X509* cert;
                    STACK_OF(X509)* ca = NULL;

                    p12DS = d2i_PKCS12_fp(fp, &p12DS);
                    fclose(fp);
                    // read the pass phrase
                    char passValue[MAX_STRING_LENGTH] = "";
                    BOOL passFound = FALSE;
                    IO_ReadStringInstance(
                                  nodeId,
                                  ANY_ADDRESS,
                                  pkiConfigurationInput,
                                  "PRECONFIGURED-CERTIFICATE-PASSPHRASE",
                                  instanceIndex,
                                  TRUE,
                                  &passFound,
                                  passValue);
                    result = PKCS12_parse(p12DS,
                                          passValue,
                                          &pkey,
                                          &cert,
                                          &ca);
                    isPemFormat = FALSE;
                    if (result && cert != NULL)
                    {
                        PKIInsertCertificate(value,
                            cert,
                            node,
                            isPemFormat,
                            passValue,
                            pkiConfigurationInput,
                            instanceIndex,
                            pkey);
                    }
                    else
                    {
                        ERROR_ReportError(
                               "Could not read the P12 certificate file \n");
                    }
                }
            }
            instanceIndex++;
        }
    }
}



// /**
// API        :: PKIReadSharedCertificateFileConfiguration
// LAYER      :: Network
// PURPOSE    :: To parse Shared certificate file
// PARAMETERS ::
// + node    :  Node* : node that is parsing certificate file
// + pkiConfigurationInput  :  NodeInput* : PKI configured file
// + nodeId   :  NodeId : nodeId of the node
// RETURN     :: void
// **/
static
void PKIReadSharedCertificateFileConfiguration(
    Node* node,
    NodeInput* pkiConfigurationInput,
    NodeId nodeId)
{
    int instanceIndex = 0;
    BOOL found = FALSE;
    char value[MAX_STRING_LENGTH * 2] = {};
    map<string, X509CertificateDetails*>::iterator it;
    int certCount=-1;

    IO_ReadInt(
        nodeId,
        ANY_ADDRESS,
        pkiConfigurationInput,
        "PRECONFIGURED-SHARED-CERTIFICATE-COUNT",
        &found,
        &certCount);

    if ((found) && (certCount <= 0))
    {
        ERROR_ReportError(
                    "PRECONFIGURED-SHARED-CERTIFICATE-COUNT parameter"
                    " require value greater than 0\n");
    }

    if (found)
    {
        while (instanceIndex < certCount)
        {

            IO_ReadStringInstance(
                    nodeId,
                    ANY_ADDRESS,
                    pkiConfigurationInput,
                    "PRECONFIGURED-SHARED-CERTIFICATE-FILE-TYPE",
                    instanceIndex,
                    TRUE,
                    &found,
                    value);
            //file type parameter not found
            if (!found)
            {
                instanceIndex++;
                continue;
            }

            // file type found but unknown value
            if (found &&
                strcmp(value,"PEM") != 0 && strcmp(value,"P7B") != 0)
            {
                ERROR_ReportError(
                       "PRECONFIGURED-SHARED-CERTIFICATE-FILE-TYPE parameter"
                       " can only have value PEM/P7B \n");
            }

            // PEM FORMAT
            if (found && strcmp(value,"PEM") == 0)
            {
                IO_ReadStringInstance(
                        nodeId,
                        ANY_ADDRESS,
                        pkiConfigurationInput,
                        "PRECONFIGURED-SHARED-CERTIFICATE-FILE",
                        instanceIndex,
                        TRUE,
                        &found,
                        value);

                if (!found)
                {
                    ERROR_ReportError(
                            "PRECONFIGURED-SHARED-CERTIFICATE-FILE required"
                            " parameter not found \n");
                }
                else
                {
                    FILE* f = fopen(value,"r");
                    if (f == NULL)
                    {
                        fclose(f);
                        ERROR_ReportError(
                            "Cannot Open Certificate File\n");
                    }
                    X509* certx = PEM_read_X509(f, NULL, NULL, NULL);
                    fclose(f);
                    if (certx != NULL)
                    {
                        PKIInsertCertificate(value,
                            certx,
                            node,
                            FALSE,
                            NULL,
                            pkiConfigurationInput,
                            instanceIndex,
                            NULL,
                            TRUE);
                    }
                    else
                    {
                        ERROR_ReportError(
                               "Could not read the PEM certificate file \n");
                    }
                }
            }
            //P7B format
            else if (found && strcmp(value,"P7B") == 0)
            {
                IO_ReadStringInstance(
                        nodeId,
                        ANY_ADDRESS,
                        pkiConfigurationInput,
                        "PRECONFIGURED-SHARED-CERTIFICATE-FILE",
                        instanceIndex,
                        TRUE,
                        &found,
                        value);

                if (!found)
                {
                    ERROR_ReportError(
                    "PRECONFIGURED-SHARED-CERTIFICATE-FILE required"
                    " parameter not found \n");
                }
                else
                {
                    FILE* fp1 = fopen(value, "r");
                    if (fp1 == NULL)
                    {
                        fclose(fp1);
                        ERROR_ReportError(
                            "Cannot Open Certificate File\n");
                    }
                    PKCS7* pkcs7 = NULL;
                    pkcs7 = d2i_PKCS7_fp(fp1,&pkcs7);
                    fclose(fp1);
                    if (pkcs7 == NULL)
                    {
                        ERROR_ReportError(
                            "Unrecognised P7B Certificate File\n");
                    }
                    STACK_OF(X509)* chain = pkcs7->d.sign->cert;
                    if (chain == NULL)
                    {
                        ERROR_ReportError(
                            "Error in reading P7B Certificate\n");
                    }
                    int count = sk_X509_num(chain);
                    X509* xcert = NULL;
                    for (int i = 0; i < count; i++)
                    {
                        xcert = sk_X509_value(chain,i);
                        PKIInsertCertificate(value,
                            xcert,
                            node,
                            FALSE,
                            NULL,
                            pkiConfigurationInput,
                            instanceIndex,
                            NULL,
                            TRUE);
                    }
                }
            }
            instanceIndex++;
        }
    }
}



// /**
// API        :: PKIReadCertificateConfiguration
// LAYER      :: Network
// PURPOSE    :: To read user configured certificate information
// PARAMETERS ::
// + node    :  Node* : node that is parsing certificate file
// + pkiConfigurationInput  :  NodeInput* : PKI configured file
// + nodeId   :  NodeId : nodeId of the node
// RETURN     :: void
// **/
static
void PKIReadCertificateConfiguration(
    Node* node,
    NodeInput* pkiConfigurationInput,
    NodeId nodeId)
{
    BOOL found = FALSE;
    int certCount = -1;

    map<string, X509CertificateDetails*>::iterator it;
    NetworkData* nData = &node->networkData;
    PKIData* pkiData = nData->pkiData;


    IO_ReadInt(
        nodeId,
        ANY_ADDRESS,
        pkiConfigurationInput,
        "GENERATED-CERTIFICATE-PRIVATEKEY-PAIR-COUNT",
        &found,
        &certCount);

    if ((found) && (certCount <= 0))
    {
        ERROR_ReportError(
                    "GENERATED-CERTIFICATE-PRIVATEKEY-PAIR-COUNT parameter"
                    " require value greater than 0\n");
    }

    if (found)
    {
        int certIndex = 0;
        while (certIndex < certCount)
        {
            X509CertificateDetails* certDetail = NULL;
            char commonName[MAX_STRING_LENGTH] = {};

            IO_ReadStringInstance(
                    nodeId,
                    ANY_ADDRESS,
                    pkiConfigurationInput,
                    "CERTIFICATE-OWNER-COMMONNAME",
                    certIndex,
                    TRUE,
                    &found,
                    commonName);

            if (!found)
            {
                sprintf(commonName, "QualNet_%d_%d",nodeId, certIndex);
            }

            it = pkiData->certificateList->find(commonName);

            if (it == pkiData->certificateList->end())
            {
                certDetail = new X509CertificateDetails;
                certDetail->X509CertificateInit(nodeId, certIndex);

                certDetail->PKIReadSubjectConfiguration(node,
                                                    pkiConfigurationInput,
                                                    nodeId,
                                                    certIndex);
                certDetail->PKIReadIssuerConfiguration(node,
                                                    pkiConfigurationInput,
                                                    nodeId,
                                                    certIndex);

                certDetail->PKIReadPrivateKeyConfiguration(node,
                                                     pkiConfigurationInput,
                                                     nodeId,
                                                     certIndex,
                                                     true);

                certDetail->PKIReadCertificateFileName(node,
                                                  pkiConfigurationInput,
                                                  nodeId,
                                                  certIndex);

                certDetail->PKIGenerateCertificate();

                pkiData->certificateList->insert(
                                pair<string, X509CertificateDetails*>
                                (commonName, certDetail));
            }
            else
            {
                ERROR_ReportWarning("Cannont insert certificate with"
                    " duplicate Owner-Common-Name.\n");
            }
            certIndex++;
        }
    }
}

// /**
// API        :: PKIInitialize
// LAYER      :: Network
// PURPOSE    :: Initializes the PKI structure.
// PARAMETERS ::
// + node     :  Node* : node that is initializing PKI
// + nodeInput:  const NodeInput* : Layer type to be set for this message
// RETURN     :: void
// **/
void
PKIInitialize(
    Node* node,
    const NodeInput* nodeInput)
{

    char pkiConfigurationfile[MAX_STRING_LENGTH * 2] = {};
    BOOL found = FALSE;
    NodeInput pkiConfigurationInput;
    map<string, X509CertificateDetails*>::iterator it;

    vector<int> sharedNodeList;
    PKIData* pkiData;

    NetworkData* nData = &node->networkData;

    nData->pkiData = (PKIData*)MEM_malloc(sizeof(PKIData));

    pkiData = nData->pkiData;
    memset(pkiData, 0, sizeof(PKIData));

    pkiData->certificateList = new map <string, X509CertificateDetails*>;
    pkiData->sharedCertificate = new map <string, X509CertificateDetails*>;

    IO_ReadString(
                node->nodeId,
                ANY_ADDRESS,
                nodeInput,
                "PKI-CONFIGURATION-FILE",
                &found,
                pkiConfigurationfile);

    if ((!found) || (!pkiConfigurationfile))
    {
        ERROR_ReportError(
                    "PKI-CONFIGURATION-FILE parameter is required\n");
    }

    IO_InitializeNodeInput(&pkiConfigurationInput, true);
    IO_ReadNodeInput(&pkiConfigurationInput, pkiConfigurationfile);

    PKIReadCertificateFileConfiguration(node,
                                        &pkiConfigurationInput,
                                        node->nodeId);

    PKIReadCertificateConfiguration(node,
                                    &pkiConfigurationInput,
                                    node->nodeId);

    PKIReadSharedCertificateFileConfiguration(node,
                                        &pkiConfigurationInput,
                                        node->nodeId);


}


//************************ S I G N   P A C K E T **************************

// /**
// API        :: PKISignPacket
// LAYER      :: Network
// PURPOSE    :: To sign the packet. Packet is signed with self private key,
//               but can only be verified by its pulblic key
// PARAMETERS ::
// + inPacket:  char* : packet to be signed
// + inputPacketLength :  int : length of packet to be signed
// + privateKey:  EVP_PKEY* : OpenSSL privtate key pointer
// + outPacketLength:  unsigned int* : length of signed packet will
//                                     be returned
// RETURN     :: unsigned char* : Pointer to signed packet
// **/
unsigned char*
PKISignPacket(
    char* inPacket,
    int inputPacketLength,
    EVP_PKEY* privateKey,
    unsigned int* outPacketLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc(MAX_STRING_LENGTH * 2);
    EVP_MD_CTX md_ctx;
    BOOL isSigned = FALSE;
    EVP_SignInit (&md_ctx, EVP_sha1());
    EVP_SignUpdate (&md_ctx, inPacket, inputPacketLength);
    isSigned = EVP_SignFinal (&md_ctx,
                              outPacket,
                              outPacketLength,
                              privateKey);
    if (isSigned != 1)
    {
        return NULL;
    }
    return outPacket;
}

// /**
// API        :: PKISignPacketUsingDistinguisingName
// LAYER      :: Network
// PURPOSE    :: To sign the packet using distinguishing name.
//               Packet is signed with self private key,
//               but can only be verified by its pulblic key
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + inPacket:  char* : packet to be signed
// + inputPacketLength :  int : length of packet to be signed
// + fqdn:  char* : name of the certificate issuer
// + outPacketLength:  unsigned int* : length of signed packet will 
//                                     be returned
// RETURN     :: unsigned char* : Pointer to signed packet
// **/
unsigned char*
PKISignPacketUsingDistinguisingName(
    Node* node,
    char* inPacket,
    int inputPacketLength,
    char* fqdn,
    unsigned int* outPacketLength)
{
    NetworkData* networkData  =  &node->networkData;
    PKIData* pkiData = networkData->pkiData;

    map<string, X509CertificateDetails*>::iterator it;
    it = pkiData->certificateList->find(fqdn);

    if (it == pkiData->certificateList->end())
    {
        return NULL;
    }

    return PKISignPacketUsingX509CertificateDetails(
                                                    inPacket,
                                                    inputPacketLength,
                                                    it->second,
                                                    outPacketLength);
}

// /**
// API        :: PKISignPacketUsingX509CertificateDetails
// LAYER      :: Network
// PURPOSE    :: To sign the packet using X509CertificateDetails.
//               Packet is signed with self private key,
//               but can only be verified by its pulblic key
// PARAMETERS ::
// + inPacket:  char* : packet to be signed
// + inputPacketLength :  int : length of packet to be signed
// + certificateDetails:  X509CertificateDetails* : certificate pointer
// + outPacketLength:  unsigned int* : length of signed packet will 
//                                     be returned
// RETURN     :: unsigned char* : Pointer to signed packet
// **/
unsigned char*
PKISignPacketUsingX509CertificateDetails(
    char* inPacket,
    int inputPacketLength,
    X509CertificateDetails* certificateDetails,
    unsigned int* outPacketLength)
{
    X509* cert = NULL;
    EVP_PKEY* pKey = NULL;

    if (certificateDetails == NULL)
    {
        return NULL;
    }

    cert = certificateDetails->PKIGetCertificate();
    pKey = certificateDetails->PKIGetPrivateKey();

    if (cert == NULL || pKey == NULL)
    {
        ERROR_ReportError(
                "Cannot Sign Packet.Error in Certificate or PrivateKey \n");
    }

    if (cert != NULL && pKey != NULL)
    {
        return PKISignPacket(
                    inPacket,
                    inputPacketLength,
                    pKey,
                    outPacketLength);
    }
    else
    {
        return NULL;
    }
}


//********************V E R I F Y   S I G N E D   P A C K E T *************

// /**
// API        :: PKIVerifySignedPacket
// LAYER      :: Network
// PURPOSE    :: To verify the signed the packet.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + dataPacket:  char* : input packet which need to be verify
// + dataPacketSize :  int : input packet length
// + signPacket:  unsigned char* : signature of input packet
// + signPacketSize :  unsigned int : signature length
// + fqdn:  char* : certificate's issuer name
// RETURN     :: BOOL : returns true if the signature is valid
// **/
BOOL
PKIVerifySignedPacket(
    Node* node,
    char* dataPacket,
    int dataPacketSize,
    unsigned char* signPacket,
    unsigned int signPacketSize,
    char* fqdn)
{
    EVP_MD_CTX md_ctx;
    EVP_PKEY* publickey = NULL;
    X509* certificate = NULL;
    map<string, X509CertificateDetails*>::iterator it;
    NetworkData* networkData  =  &node->networkData;
    PKIData* pkiData = networkData->pkiData;
    BOOL isVerified = FALSE;

    it = pkiData->sharedCertificate->find(fqdn);

    if (it == pkiData->sharedCertificate->end())
    {
        ERROR_ReportError(
            "Can not Verify the signature");
    }
    X509CertificateDetails* certificateDetails = it->second;

    certificate = certificateDetails->PKIGetCertificate();

    if (certificate != NULL)
    {
        publickey = X509_get_pubkey(certificate);
        if (publickey == NULL)
        {
            return isVerified;
        }
        EVP_VerifyInit(&md_ctx, EVP_sha1());
        EVP_VerifyUpdate(&md_ctx, dataPacket, dataPacketSize);
        isVerified = EVP_VerifyFinal(&md_ctx, signPacket,
                     signPacketSize, publickey);
        EVP_PKEY_free(publickey);
        return isVerified;
    }
    else
    {
        return FALSE;
    }


}

// /**
// API        :: PKIVerifySignedPacketUsingDataOffset
// LAYER      :: Network
// PURPOSE    :: To verify the signed the packet.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + dataPacket:  char* : input packet which need to be verify
// + dataPacketStartOffset :  int : starting offset of input packet
// + dataPacketEndOffset:  int :  end offset of input packet
// + signPacketStartOffset :  int :  starting offset of signature
// + signPacketEndOffset:  int :  end offset of input signature
// + fqdn:  char* : certificate's issuer name
// RETURN     :: BOOL : returns true if the signature is valid
// **/
BOOL
PKIVerifySignedPacketUsingDataOffset(
    Node* node,
    char* dataPacket,
    int dataPacketStartOffset,
    int dataPacketEndOffset,
    int signPacketStartOffset,
    int signPacketEndOffset,
    char* fqdn)
{
    return PKIVerifySignedPacket(
                node,
                (char*)dataPacket + dataPacketStartOffset,
                dataPacketEndOffset - dataPacketStartOffset,
                (unsigned char*)dataPacket + signPacketStartOffset,
                signPacketEndOffset - signPacketStartOffset,
                fqdn);
}


//*********************** E N C R Y P T   P A C K E T *****************

// /**
// API        :: PKIEncryptPacket
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet.
// PARAMETERS ::
// + inPacket:  char* : input packet which need to encrypt
// + inputPacketLength :  int : packet length which need to encrypt
// + certificateDetails:  X509* :  OpenSSL certificate pointer
// + outPacketLength :  int* :  encrypted packet length
// RETURN     :: char* : encrypted packet
// **/
char*
PKIEncryptPacket(
    char* inPacket,
    int inputPacketLength,
    X509* certificateDetails,
    int* outPacketLength)
{
    BIO* in = NULL;
    BIO* out = NULL;
    STACK_OF(X509)* chain;
    PKCS7* pkcs7 = NULL;
    char* outPacket = NULL;
    EVP_CIPHER* cipher = (EVP_CIPHER*) EVP_des_ede3_cbc();


    in = BIO_new(BIO_s_mem());
    out = BIO_new(BIO_s_mem());//BIO_new_fp(stdout, BIO_NOCLOSE);

    chain = sk_X509_new_null();

    sk_X509_push(chain, certificateDetails);

    BIO_write(in, inPacket ,inputPacketLength);

    pkcs7 = PKCS7_encrypt(chain, in , cipher, PKCS7_BINARY);
    if (!pkcs7)
    {
        BIO_free(in);
        BIO_free(out);
        return NULL;
    }

    if (SMIME_write_PKCS7(out, pkcs7, in, 0) != 1)
    {
        BIO_free(in);
        BIO_free(out);
        return NULL;
    }

    *outPacketLength = out->num_write;
    outPacket = (char*)MEM_malloc(*outPacketLength + 1);
    memset(outPacket, 0, *outPacketLength + 1);

    BIO_read(out, outPacket, *outPacketLength);


    BIO_free(in);
    BIO_free(out);
    return outPacket;
}

// /**
// API        :: PKIEncryptPacketInMessageUsingDistinguisingName
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet in Message using Distinguising Name.
// PARAMETERS ::
// + node  :  Node* : node which is allocating the space
// + msg   :  Message* : message which need to encrypt
// + fqdn  :  char* : certificate's issuer name
// RETURN     :: BOOL :  returns true if message is encryped successfully
// **/
BOOL
PKIEncryptPacketInMessageUsingDistinguisingName(
    Node* node,
    Message* msg,
    char* fqdn)
{
    map<string, X509CertificateDetails*>::iterator it;

    NetworkData* networkData = &node->networkData;
    PKIData* pkiData = networkData->pkiData;

    if (fqdn == NULL)
    {
        return FALSE;
    }

    it = pkiData->sharedCertificate->find(fqdn);

    if (it != pkiData->sharedCertificate->end())
    {
        return PKIEncryptPacketInMessageUsingX509CertificateDetails(
                                node,
                                msg,
                                it->second);
    }
    return FALSE;
}

// /**
// API        :: PKIEncryptPacketInMessageUsingX509CertificateDetails
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet in Message using.X509CertificateDetails
// PARAMETERS ::
// + node  :  Node* : node which is allocating the space
// + msg   :  Message* : message which need to encrypt
// + certificateDetails  :  X509CertificateDetails* : pointer of certificate
// RETURN     :: BOOL :  returns true if message is encryped successfully
// **/
BOOL
PKIEncryptPacketInMessageUsingX509CertificateDetails(
    Node* node,
    Message* msg,
    X509CertificateDetails* certificateDetails)
{
    X509* cert;
    char* inPacket;
    char* outPacket = NULL;
    int outPacketLength = 0;

    cert = certificateDetails->PKIGetCertificate();

    if (cert == NULL)
    {
        return FALSE;
    }

    if (MESSAGE_ReturnActualPacketSize(msg) == 0)
    {
        return FALSE;
    }

    inPacket = (char*) MEM_malloc(MESSAGE_ReturnActualPacketSize(msg));

    memcpy(inPacket, MESSAGE_ReturnPacket(msg),
                                        MESSAGE_ReturnActualPacketSize(msg));

    outPacket = PKIEncryptPacket(inPacket,
                            MESSAGE_ReturnActualPacketSize(msg),
                            cert,
                            &outPacketLength);

    MEM_free(inPacket);

    if (outPacket == NULL)
    {
        return FALSE;
    }
    char* packet = NULL;
    PKIPacketRealloc(node, msg, outPacketLength);
    packet = MESSAGE_ReturnPacket(msg);
    memcpy(packet, outPacket, outPacketLength);

    MEM_free(outPacket);
    return TRUE;
}


// /**
// API        :: PKIEncryptPacketUsingDistinguisingName
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet using Distinguising Name.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + packet:  char* : input packet which need to encrypt
// + inputPacketLength :  int : packet length which need to encrypt
// + fqdn:  char* :  certificate's issuer name
// + outPacketLength :  int* :  encrypted packet length
// RETURN     :: char* : encrypted packet
// **/
char*
PKIEncryptPacketUsingDistinguisingName(
    Node* node,
    char* packet,
    int inputPacketLength,
    char* fqdn,
    int* outPacketLength)
{
    map<string, X509CertificateDetails*>::iterator it;

    NetworkData* networkData  =  &node->networkData;
    PKIData* pkiData = networkData->pkiData;

    if (fqdn == NULL)
    {
        return NULL;
    }

    it = pkiData->sharedCertificate->find(fqdn);

    if (it != pkiData->sharedCertificate->end())
    {
        return PKIEncryptPacketUsingX509CertificateDetails(
                                packet,
                                inputPacketLength,
                                it->second,
                                outPacketLength);
    }
    return NULL;
}


// /**
// API        :: PKIEncryptPacketUsingX509CertificateDetails
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet using.X509CertificateDetails
// PARAMETERS ::
// + packet:  char* : input packet which need to encrypt
// + inputPacketLength :  int : packet length which need to encrypt
// + certificateDetails:  X509CertificateDetails* :  certificate pointer
// + outPacketLength :  int* :  encrypted packet length
// RETURN     :: char* : encrypted packet
// **/
char*
PKIEncryptPacketUsingX509CertificateDetails(
    char* packet,
    int inputPacketLength,
    X509CertificateDetails* certificateDetails,
    int* outPacketLength)
{
    X509* cert;

    cert = certificateDetails->PKIGetCertificate();
    if (!cert)
    {
        return NULL;
    }

    return PKIEncryptPacket(packet,
                            inputPacketLength,
                            cert,
                            outPacketLength);
}


//*********************** D E C R Y P T   P A C K E T *****************

// /**
// API        :: PKIDecryptPacket
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet.
// PARAMETERS ::
// + inPacket:  char* : input packet which need to decrypt
// + inPacketSize :  int : packet length which need to decrypt
// + certificateDetails:  X509* :  certificate pointer
// + privateKey :  EVP_PKEY* :  private key to decrypt the packet
// + outPacketSize :  int* :  packet length of decrypted Packet
// RETURN     :: char* : decrypted packet
// **/
char*
PKIDecryptPacket(
    char* inPacket,
    int inPacketSize,
    X509* certificateDetails,
    EVP_PKEY* privateKey,
    int* outPacketLength)
{
    char* outPacket = NULL;

    BIO* in = NULL;
    BIO* out = NULL;
    BIO* cont = NULL;


    int decryptStatus = -1;
    char errbuf[MAX_STRING_LENGTH];

    in = BIO_new_mem_buf(inPacket, inPacketSize);
    out = BIO_new(BIO_s_mem());

    PKCS7* pkcs7 = SMIME_read_PKCS7(in, &cont);

    decryptStatus = PKCS7_decrypt(pkcs7, privateKey,
                                certificateDetails,out, 0);

    if (decryptStatus == 1)
    {
        *outPacketLength = out->num_write;
        outPacket = (char*)MEM_malloc(*outPacketLength);
        BIO_read(out, outPacket, *outPacketLength);
    }
    else
    {
        ERR_error_string(ERR_get_error(), errbuf);
        puts(errbuf);
    }

    BIO_free(in);
    BIO_free(out);

    return outPacket;
}

// /**
// API        :: PKIDecryptPacketInMessage
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet in Message.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + msg:  Message* : message which need to decrypt
// + crtDetails:  X509* :  certificate pointer
// + privateKey :  EVP_PKEY* :  private key to decrypt the packet
// RETURN     :: BOOL : true if message is decrypted successfully
// **/
BOOL
PKIDecryptPacketInMessage(
    Node* node,
    Message* msg,
    X509* crtDetails,
    EVP_PKEY* privateKey)
{
    char* inPacket = NULL;
    char* outPacket = NULL;
    int outPacketLength = 0;

    inPacket = (char*) MEM_malloc(MESSAGE_ReturnActualPacketSize(msg));

    memcpy(inPacket, MESSAGE_ReturnPacket(msg),
                                        MESSAGE_ReturnActualPacketSize(msg));

    outPacket = PKIDecryptPacket(
                        inPacket,
                        MESSAGE_ReturnActualPacketSize(msg),
                        crtDetails,
                        privateKey,
                        &outPacketLength);

    if (outPacket)
    {
        char* packet = NULL;
        PKIPacketRealloc(node, msg, outPacketLength);
        packet = MESSAGE_ReturnPacket(msg);
        memcpy(packet, outPacket, outPacketLength);
        MEM_free(outPacket);
        MEM_free(inPacket);
        return TRUE;
    }
    else
    {
        MEM_free(inPacket);
        return FALSE;
    }
}

// /**
// API        :: PKIDecryptPacketInMessageUsingDistinguisingName
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet in Message using Distinguising Name.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + msg:  Message* : message which need to decrypt
// + fqdn:  char* :  certificate's issuer name
// RETURN     :: BOOL : true if message is decrypted successfully
// **/
BOOL
PKIDecryptPacketInMessageUsingDistinguisingName(
    Node* node,
    Message* msg,
    char* fqdn)
{
    map<string, X509CertificateDetails*>::iterator it;

    NetworkData* nData = &node->networkData;
    PKIData* pkiData = nData->pkiData;

    if (fqdn == NULL)
    {
        return FALSE;
    }

    it = pkiData->certificateList->find(fqdn);

    if (it != pkiData->certificateList->end())
    {
        return PKIDecryptPacketInMessageUsingX509CertificateDetails(
                        node,
                        msg,
                        it->second);
    }
    return FALSE;
}

// /**
// API        :: PKIDecryptPacketInMessageUsingX509CertificateDetails
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet.in Message using X509CertificateDetails
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + msg:  Message* : message which need to decrypt
// + certificateDetails:  X509CertificateDetails* :  certificate pointer
// RETURN     :: BOOL : true if message is decrypted successfully
// **/
BOOL
PKIDecryptPacketInMessageUsingX509CertificateDetails(
    Node* node,
    Message* msg,
    X509CertificateDetails* certificateDetails)
{
    X509* cert = NULL;
    EVP_PKEY* pKey = NULL;

    if (certificateDetails == NULL)
    {
        return FALSE;
    }

    cert = certificateDetails->PKIGetCertificate();
    pKey = certificateDetails->PKIGetPrivateKey();

    if (cert != NULL && pKey != NULL)
    {
        return PKIDecryptPacketInMessage(
                node,
                msg,
                cert,
                pKey);
    }
    else
    {
        return FALSE;
    }


}

// /**
// API        :: PKIDecryptPacketUsingDistinguisingName
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet using Distinguising Name.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + inPacket:  char* : input packet which need to decrypt
// + inPacketSize :  int : packet length which need to decrypt
// + fqdn:  char* :  distinguishing name
// + outPacketSize :  int* :  packet length of decrypted Packet
// RETURN     :: char* : decrypted packet
// **/
char*
PKIDecryptPacketUsingDistinguisingName(
    Node* node,
    char* packet,
    int inputPacketLength,
    char* fqdn,
    int* outPacketLength)
{
    map<string, X509CertificateDetails*>::iterator it;

    NetworkData* nData = &node->networkData;
    PKIData* pkiData = nData->pkiData;

    if (fqdn == NULL)
    {
        return NULL;
    }

    it = pkiData->certificateList->find(fqdn);

    if (it != pkiData->certificateList->end())
    {
        return PKIDecryptPacketUsingX509CertificateDetails(
                        packet,
                        inputPacketLength,
                        it->second,
                        outPacketLength);
    }
    return NULL;
}

// /**
// API        :: PKIDecryptPacketUsingX509CertificateDetails
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet using X509CertificateDetails
// PARAMETERS ::
// + inPacket:  char* : input packet which need to decrypt
// + inPacketSize :  int : packet length which need to decrypt
// + certificateDetails:  X509* :  certificate pointer
// + outPacketSize :  int* :  packet length of decrypted Packet
// RETURN     :: char* : decrypted packet
// **/
char*
PKIDecryptPacketUsingX509CertificateDetails(
    char* packet,
    int inputPacketLength,
    X509CertificateDetails* certificateDetails,
    int* outPacketLength)
{
    X509* crtDetails = NULL;
    EVP_PKEY* privateKey = NULL;

    if (certificateDetails == NULL)
    {
        return NULL;
    }

    crtDetails = certificateDetails->PKIGetCertificate();
    if (crtDetails == NULL)
    {
        return NULL;
    }

    privateKey = certificateDetails->PKIGetPrivateKey();
    if (privateKey == NULL)
    {
        return NULL;
    }

    return PKIDecryptPacket(
                packet,
                inputPacketLength,
                crtDetails,
                privateKey,
                outPacketLength);
}

// /**
// API        :: opensslInitForPKI
// LAYER      :: Network
// PURPOSE    :: To init the openssl common methods
// PARAMETERS :: void
// RETURN     :: void
// **/
void
PKIOpensslInit()
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}


// /**
// API        :: isPkiEnabledForAnyNode
// LAYER      :: Network
// PURPOSE    :: To check if pki is enabled for any node or not
// PARAMETERS ::
// + numOfNodes :  int : number of nodes in scenario
// + nodeInput  :  NodeInput* : config file
// RETURN     :: BOOL
// **/
BOOL
PKIIsEnabledForAnyNode(int numOfNodes, const NodeInput* nodeInput)
{

    BOOL found;
    BOOL readValue;
    char value[MAX_STRING_LENGTH];
    for (unsigned int i = 0; i < numOfNodes; i++)
    {
        IO_ReadBool(i,
                    ANY_ADDRESS,
                    nodeInput,
                    "PKI-ENABLED",
                    &found,
                    &readValue);
        if (found == TRUE && readValue)
        {
            return true;
        }
    }
    return false;
}


// /**
// API        :: PKIFinalize
// LAYER      :: Network
// PURPOSE    :: Finalize method for PKI.It frees any allocated memory to the
//               pkiData in networkData structure of Node.
// PARAMETERS ::
// + node : Node* : Pointer to node
// RETURN     :: void
// **/
void PKIFinalize(Node* node)
{
    map<string, X509CertificateDetails*>::iterator it;

    for (it = node->networkData.pkiData->certificateList->begin();
         it != node->networkData.pkiData->certificateList->end();
         it++)
    {
        if (it->second->certificate != NULL)
        {
            X509_free(it->second->certificate);
        }
        if (it->second->privateKey != NULL)
        {
            EVP_PKEY_free(it->second->privateKey);
        }
    }

    for (it = node->networkData.pkiData->sharedCertificate->begin();
         it != node->networkData.pkiData->sharedCertificate->end();
         it++)
    {
        if (it->second->certificate != NULL)
        {
            X509_free(it->second->certificate);
        }
    }
}
// /**
// API       :: PKIPacketRealloc
// LAYER     :: Network
// PURPOSE   :: To allocate new space for the packet
//              and return the payload with the new packet. It is mandatory
//              that the packet should be Non null while calling this
//              function. The previous packet content would be retained in
//              the newly allocated packet.
// PARAMETERS::
// + node    : Node* : node which is assembling the packet
// + msg: Message*  : message to reallocate
// + newPacketSize: int  : new packet size
// RETURN    :: void
// **/
void PKIPacketRealloc(Node* node,
                      Message* msg,
                      int newPacketSize)
{
    assert(msg->payload != NULL);
    assert(msg->packet != NULL);

    char* payload;
    int previousPayloadSize = 0;

    /* Reallocate the payload with the new packetsize.
     * The msg->payloadSize includes msg->packetSize, hence in order to
     * incorporate the newPacketSize, we need to subtract the  packetSize
     * before adding the newPacketSize */
    previousPayloadSize = msg->payloadSize - msg->packetSize;
    payload = MESSAGE_PayloadAlloc(
                   node->partitionData,
                   previousPayloadSize + newPacketSize,
                   msg->mtWasMT);

    //Copy old packet to last minPktSize bytes of new payload
    int minPktSize =
       (newPacketSize <= msg->packetSize ? newPacketSize : msg->packetSize);
    int endOfPayload = previousPayloadSize + newPacketSize - minPktSize;
    memcpy(payload + endOfPayload,
           msg->packet,
           minPktSize);

    /* Now free the previous payload*/
    MESSAGE_PayloadFree(node->partitionData,
            msg->payload,
            msg->payloadSize,
            msg->mtWasMT);

    msg->payload = payload;
    msg->packet = msg->payload + previousPayloadSize;
    msg->payloadSize = previousPayloadSize + newPacketSize;
    msg->packetSize = newPacketSize;

    return;
}
