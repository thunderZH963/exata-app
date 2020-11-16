#ifndef NETSEC_PKI_STRUCT_H
#define NETSEC_PKI_STRUCT_H

#include <openssl/evp.h>

enum PrivateKeyType {
    DSA_KEY,
    RSA_KEY,
    NO_KEY
};

enum ValidityInfoType {
    PKI_YEAR,
    PKI_MONTH,
    PKI_DAY,
    PKI_HOUR,
    PKI_MIN,
    PKI_SEC
};

struct X509CertificateDetails
{
    string subjectCountryName;
    string subjectStateName;
    string subjectLocation;
    string subjectOrganizationName;
    string subjectOrganizationUnit;
    string subjectCommonName;
    string subjectEmail;
    string subjectDistinguishName; 

    string issuerCountryName;
    string issuerStateName;
    string issuerLocation;
    string issuerOrganizationName;
    string issuerOrganizationUnit;
    string issuerCommonName;
    string issuerEmail;

    // For Certificate
    X509* certificate;
    string certificateFileName;
    // For Private Key
    EVP_PKEY* privateKey;
    string privateKeyFileName;
    PrivateKeyType privateKeyType;
    string passphrase;

    public:

// /**
// API        :: PKISet__
// LAYER      :: Network
// PURPOSE    :: Following are Set methods for struct X509CertificateDetails
// **/
    void PKISetSubjectCountryName(const char*);
    void PKISetSubjectStateName(const char*);
    void PKISetSubjectLocation(const char*);
    void PKISetSubjectOrganizationName(const char*);
    void PKISetSubjectOrganizationUnit(const char*);
    void PKISetSubjectCommonName(const char*);
    void PKISetSubjectEmail(const char*);
    void PKISetSubjectDistinguishName(const char*);
    void PKISetIssuerCountryName(const char*);
    void PKISetIssuerStateName(const char*);
    void PKISetIssuerLocation(const char*);
    void PKISetIssuerOrganizationName(const char*);
    void PKISetIssuerOrganizationUnit(const char*);
    void PKISetIssuerCommonName(const char*);
    void PKISetIssuerEmail(const char*);
    void PKISetCertificate(X509*);
    void PKISetPrivateKey(EVP_PKEY*);
    void PKISetCertificateFileName(const char*);
    void PKISetPrivateKeyFileName(const char*);
    void PKISetPrivateKeyType(PrivateKeyType keyType);
    void PKISetPassphrase(const char*);


// /**
// API        :: PKIGet__
// LAYER      :: Network
// PURPOSE    :: Following are Get methods for struct X509CertificateDetails
// **/
    string PKIGetSubjectCountryName();
    string PKIGetSubjectStateName();
    string PKIGetSubjectLocation();
    string PKIGetSubjectOrganizationName();
    string PKIGetSubjectOrganizationUnit();
    string PKIGetSubjectCommonName();
    string PKIGetSubjectEmail();
    string PKIGetSubjectDistinguishName();
    string PKIGetIssuerCountryName();
    string PKIGetIssuerStateName();
    string PKIGetIssuerLocation();
    string PKIGetIssuerOrganizationName();
    string PKIGetIssuerOrganizationUnit();
    string PKIGetIssuerCommonName();
    string PKIGetIssuerEmail();
    X509* PKIGetCertificate();
    EVP_PKEY* PKIGetPrivateKey();
    string PKIGetCertificateFileName();
    string PKIGetPrivateKeyFileName();
    PrivateKeyType PKIGetPrivateKeytype();
    string PKIGetPassphrase();

// /**
// API        :: X509CertificateInit
// LAYER      :: Network
// PURPOSE    :: To initialize the certificate.
// PARAMETERS ::
// + nodeId:  NodeId : owner node of certificate
// + instanceIndex :  int : certificate instance
// RETURN     :: void
// **/
    void X509CertificateInit(
            NodeId nodeId,
            int instanceIndex);

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
    void PKIReadSubjectConfiguration(
            Node* node,
            const NodeInput* nodeInput,
            NodeId nodeId,
            int instanceIndex);

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
    void PKIReadIssuerConfiguration(
            Node* node,
            const NodeInput* nodeInput,
            NodeId nodeId,
            int instanceIndex);

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
    void PKIReadPrivateKeyConfiguration(
            Node* node,
            const NodeInput* nodeInput,
            NodeId nodeId,
            int instanceIndex,
            bool wantNewKey);

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
    void PKIReadCertificateFileName(
            Node* node,
            const NodeInput* nodeInput,
            NodeId nodeId,
            int instanceIndex);

// /**
// API        :: PKIParseCertificateFile
// LAYER      :: Network
// PURPOSE    :: To get certificate information from certificate file
// PARAMETERS ::
// + fileName:  char* : certificate filename
// RETURN     :: void
// **/
    void PKIParseCertificateFile(X509* certx);

// /**
// API        :: PKIGenerateCertificate
// LAYER      :: Network
// PURPOSE    :: To generate encrypted certificate file from
//               certificate information
// PARAMETERS ::
// RETURN     :: BOOL : TRUE if certificate is generated
// **/
    BOOL PKIGenerateCertificate();
};

// /**
// API        :: PKIInitialize
// LAYER      :: Network
// PURPOSE    :: Initializes the PKI structure.
// PARAMETERS ::
// + node     :  Node* : node that is initializing PKI
// + nodeInput:  const NodeInput* : Layer type to be set for this message
// RETURN     :: void
// **/
void PKIInitialize(
    Node* node,
    const NodeInput* nodeInput);

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
unsigned char* PKISignPacketUsingDistinguisingName(
    Node* node,
    char* inPacket,
    int inputPacketLength,
    char* fqdn,
    unsigned int* outPacketLength);

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
unsigned char* PKISignPacketUsingX509CertificateDetails(
    char* inPacket,
    int inputPacketLength,
    X509CertificateDetails* certificateDetails,
    unsigned int* outPacketLength);

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
BOOL PKIVerifySignedPacketUsingDataOffset(
    Node* node,
    char* dataPacket,
    int dataPacketStartOffset,
    int dataPacketEndOffset,
    int signPacketStartOffset,
    int signPacketEndOffset,
    char* fqdn);

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
BOOL PKIVerifySignedPacket(
    Node* node,
    char* dataPacket,
    int dataPacketSize,
    unsigned char* signPacket,
    unsigned int signPacketSize,
    char* fqdn);

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
BOOL PKIEncryptPacketInMessageUsingDistinguisingName(
    Node* node,
    Message* msg,
    char* fqdn);

// /**
// API        :: PKIEncryptPacketInMessageUsingX509CertificateDetails
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet in Message using.X509CertificateDetails
// PARAMETERS ::
// + node  :  Node* : node which is allocating the space
// + msg   :  Message* : message which need to encrypt
// + certificateDetails  :  X509CertificateDetails* : pointer of certificate
// + fqdn:  char* :  certificate's issuer name
// RETURN     :: BOOL :  returns true if message is encryped successfully
// **/
BOOL PKIEncryptPacketInMessageUsingX509CertificateDetails(
    Node* node,
    Message* msg,
    X509CertificateDetails* certificateDetails);

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
char* PKIEncryptPacketUsingDistinguisingName(
    Node* node,
    char* packet,
    int inputPacketLength,
    char* fqdn,
    int* outPacketLength);

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
char* PKIEncryptPacketUsingX509CertificateDetails(
    char* packet,
    int inputPacketLength,
    X509CertificateDetails* certificateDetails,
    int* outPacketLength);

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
BOOL PKIDecryptPacketInMessageUsingDistinguisingName(
    Node* node,
    Message* msg,
    char* fqdn);

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
BOOL PKIDecryptPacketInMessageUsingX509CertificateDetails(
    Node* node,
    Message* msg,
    X509CertificateDetails* certificateDetails);

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
char* PKIDecryptPacketUsingDistinguisingName(
    Node* node,
    char* packet,
    int inputPacketLength,
    char* fqdn,
    int* outPacketLength);

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
char* PKIDecryptPacketUsingX509CertificateDetails(
    char* packet,
    int inputPacketLength,
    X509CertificateDetails* certificateDetails,
    int* outPacketLength);

// /**
// API        :: PKIOpensslInit
// LAYER      :: Network
// PURPOSE    :: To init the openssl common methods
// PARAMETERS :: void
// RETURN     :: void
// **/
void PKIOpensslInit();

// /**
// API        :: PKIIsEnabledForAnyNode
// LAYER      :: Network
// PURPOSE    :: To check if pki is enabled for any node or not
// PARAMETERS ::
// + numOfNodes :  int : number of nodes in scenario
// + nodeInput  :  NodeInput* : config file
// RETURN     :: BOOL
// **/
BOOL PKIIsEnabledForAnyNode(int numOfNodes , const NodeInput* nodeInput);

// /**
// API        :: PKIFinalize
// LAYER      :: Network
// PURPOSE    :: Finalize method for PKI.It frees any allocated memory to the
//               pkiData in networkData structure of Node.
// PARAMETERS ::
// + node : Node* : Pointer to node
// RETURN     :: void
// **/
void PKIFinalize(Node* node);

#endif
