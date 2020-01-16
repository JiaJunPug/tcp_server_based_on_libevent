ASN_MODULE_SOURCES=	\
	Attribute.c	\
	AttributeType.c	\
	AttributeValue.c	\
	AttributeTypeAndValue.c	\
	X520name.c	\
	X520CommonName.c	\
	X520LocalityName.c	\
	X520StateOrProvinceName.c	\
	X520OrganizationName.c	\
	X520OrganizationalUnitName.c	\
	X520Title.c	\
	X520dnQualifier.c	\
	X520countryName.c	\
	X520SerialNumber.c	\
	X520Pseudonym.c	\
	DomainComponent.c	\
	EmailAddress.c	\
	Name.c	\
	RDNSequence.c	\
	DistinguishedName.c	\
	RelativeDistinguishedName.c	\
	DirectoryString.c	\
	Certificate.c	\
	TBSCertificate.c	\
	Version.c	\
	CertificateSerialNumber.c	\
	Validity.c	\
	Time.c	\
	UniqueIdentifier.c	\
	SubjectPublicKeyInfo.c	\
	Extensions.c	\
	Extension.c	\
	CertificateList.c	\
	TBSCertList.c	\
	AlgorithmIdentifier.c	\
	ORAddress.c	\
	BuiltInStandardAttributes.c	\
	CountryName.c	\
	AdministrationDomainName.c	\
	NetworkAddress.c	\
	X121Address.c	\
	TerminalIdentifier.c	\
	PrivateDomainName.c	\
	OrganizationName.c	\
	NumericUserIdentifier.c	\
	PersonalName.c	\
	OrganizationalUnitNames.c	\
	OrganizationalUnitName.c	\
	BuiltInDomainDefinedAttributes.c	\
	BuiltInDomainDefinedAttribute.c	\
	ExtensionAttributes.c	\
	ExtensionAttribute.c	\
	CommonName.c	\
	TeletexCommonName.c	\
	TeletexOrganizationName.c	\
	TeletexPersonalName.c	\
	TeletexOrganizationalUnitNames.c	\
	TeletexOrganizationalUnitName.c	\
	PDSName.c	\
	PhysicalDeliveryCountryName.c	\
	PostalCode.c	\
	PhysicalDeliveryOfficeName.c	\
	PhysicalDeliveryOfficeNumber.c	\
	ExtensionORAddressComponents.c	\
	PhysicalDeliveryPersonalName.c	\
	PhysicalDeliveryOrganizationName.c	\
	ExtensionPhysicalDeliveryAddressComponents.c	\
	UnformattedPostalAddress.c	\
	StreetAddress.c	\
	PostOfficeBoxAddress.c	\
	PosteRestanteAddress.c	\
	UniquePostalName.c	\
	LocalPostalAttributes.c	\
	PDSParameter.c	\
	ExtendedNetworkAddress.c	\
	PresentationAddress.c	\
	TerminalType.c	\
	TeletexDomainDefinedAttributes.c	\
	TeletexDomainDefinedAttribute.c	\
	SVSVersion.c	\
	ReqType.c	\
	ExportCertReq.c	\
	ExportCertResp.c	\
	ParseCertReq.c	\
	ParseCertResp.c	\
	ValidateCertReq.c	\
	ValidateCertResp.c	\
	SignDataReq.c	\
	SignDataResp.c	\
	VerifySignedDataReq.c	\
	VerifySignedDataResp.c	\
	SignDataInitReq.c	\
	SignDataInitResp.c	\
	SignDataUpdateReq.c	\
	SignDataUpdateResp.c	\
	SignDataFinalReq.c	\
	SignDataFinalResp.c	\
	VerifySignedDataInitReq.c	\
	VerifySignedDataInitResp.c	\
	VerifySignedDataUpdateReq.c	\
	VerifySignedDataUpdateResp.c	\
	VerifySignedDataFinalReq.c	\
	VerifySignedDataFinalResp.c	\
	SignMessageReq.c	\
	SignMessageResp.c	\
	VerifySignedMessageReq.c	\
	VerifySignedMessageResp.c	\
	SignMessageInitReq.c	\
	SignMessageInitResp.c	\
	SignMessageUpdateReq.c	\
	SignMessageUpdateResp.c	\
	SignMessageFinalReq.c	\
	SignMessageFinalResp.c	\
	VerifySignedMessageInitReq.c	\
	VerifySignedMessageInitResp.c	\
	VerifySignedMessageUpdateReq.c	\
	VerifySignedMessageUpdateResp.c	\
	VerifySignedMessageFinalReq.c	\
	VerifySignedMessageFinalResp.c	\
	SetCertTrustListReq.c	\
	GetCertTrustListAltNamesReq.c	\
	GetCertTrustListReq.c	\
	DelCertTrustListReq.c	\
	InitCertAppPolicyReq.c	\
	GetServerCertificateReq.c	\
	GenRandomReq.c	\
	GetCertInfoByOidReq.c	\
	EncryptDataReq.c	\
	DecryptDataReq.c	\
	CreateTimeStampRequestReq.c	\
	CreateTimeStampResponseReq.c	\
	VerifyTimeStampReq.c	\
	GetTimeStampInfoReq.c	\
	SetCertTrustListResp.c	\
	GetCertTrustListAltNamesResp.c	\
	GetCertTrustListResp.c	\
	DelCertTrustListResp.c	\
	InitCertAppPolicyResp.c	\
	GetServerCertificateResp.c	\
	GenRandomResp.c	\
	GetCertInfoByOidResp.c	\
	EncryptDataResp.c	\
	DecryptDataResp.c	\
	CreateTimeStampRequestResp.c	\
	CreateTimeStampResponseResp.c	\
	VerifyTimeStampResp.c	\
	GetTimeStampInfoResp.c	\
	Request.c	\
	SVSRequest.c	\
	RespStatus.c	\
	RespType.c	\
	Respond.c	\
	SVSRespond.c	\
	TimeStampReq.c	\
	MessageImprint.c	\
	TSAPolicyId.c	\
	TimeStampResq.c	\
	PKIStatusInfo.c	\
	PKIStatus.c	\
	PKIFreeText.c	\
	PKIFailureInfo.c	\
	TimeStampToken.c	\
	ContentInfo.c	\
	ContentType.c	\
	EnvelopedData.c	\
	EncryptedContentInfo.c	\
	EncryptedContent.c	\
	RecipientInfos.c	\
	RecipientInfo.c	\
	IssuerAndSerialNumber.c	\
	ContentEncryptionAlgorithmIdentifier.c	\
	KeyEncryptionAlgorithmIdentifier.c	\
	SM2Cipher.c	\
	SM2Signature.c	\
	SignedData.c	\
	DigestAlgorithmIdentifiers.c	\
	DigestAlgorithmIdentifier.c	\
	ExtendedCertificatesAndCertificates.c	\
	ExtendedCertificateOrCertificate.c	\
	ExtendedCertificate.c	\
	ExtendedCertificateInfo.c	\
	Attributes.c	\
	SignatureAlgorithmIdentifier.c	\
	Signature.c	\
	CertificateRevocationLists.c	\
	CertificateRevocationList.c	\
	SignerInfos.c	\
	SignerInfo.c	\
	DigestEncryptionAlgorithmIdentifier.c	\
	EncryptedEDigest.c	\
	SigningCertificateV2.c	\
	PolicyInformation.c	\
	CertPolicyId.c	\
	PolicyQualifierInfo.c	\
	PolicyQualifierId.c	\
	ESSCertIDv2.c	\
	Hash.c	\
	IssuerSerial.c	\
	GeneralNames.c	\
	GeneralName.c	\
	AnotherName.c	\
	EDIPartyName.c	\
	SigningCertificate.c	\
	ESSCertID.c

ASN_MODULE_HEADERS=	\
	Attribute.h	\
	AttributeType.h	\
	AttributeValue.h	\
	AttributeTypeAndValue.h	\
	X520name.h	\
	X520CommonName.h	\
	X520LocalityName.h	\
	X520StateOrProvinceName.h	\
	X520OrganizationName.h	\
	X520OrganizationalUnitName.h	\
	X520Title.h	\
	X520dnQualifier.h	\
	X520countryName.h	\
	X520SerialNumber.h	\
	X520Pseudonym.h	\
	DomainComponent.h	\
	EmailAddress.h	\
	Name.h	\
	RDNSequence.h	\
	DistinguishedName.h	\
	RelativeDistinguishedName.h	\
	DirectoryString.h	\
	Certificate.h	\
	TBSCertificate.h	\
	Version.h	\
	CertificateSerialNumber.h	\
	Validity.h	\
	Time.h	\
	UniqueIdentifier.h	\
	SubjectPublicKeyInfo.h	\
	Extensions.h	\
	Extension.h	\
	CertificateList.h	\
	TBSCertList.h	\
	AlgorithmIdentifier.h	\
	ORAddress.h	\
	BuiltInStandardAttributes.h	\
	CountryName.h	\
	AdministrationDomainName.h	\
	NetworkAddress.h	\
	X121Address.h	\
	TerminalIdentifier.h	\
	PrivateDomainName.h	\
	OrganizationName.h	\
	NumericUserIdentifier.h	\
	PersonalName.h	\
	OrganizationalUnitNames.h	\
	OrganizationalUnitName.h	\
	BuiltInDomainDefinedAttributes.h	\
	BuiltInDomainDefinedAttribute.h	\
	ExtensionAttributes.h	\
	ExtensionAttribute.h	\
	CommonName.h	\
	TeletexCommonName.h	\
	TeletexOrganizationName.h	\
	TeletexPersonalName.h	\
	TeletexOrganizationalUnitNames.h	\
	TeletexOrganizationalUnitName.h	\
	PDSName.h	\
	PhysicalDeliveryCountryName.h	\
	PostalCode.h	\
	PhysicalDeliveryOfficeName.h	\
	PhysicalDeliveryOfficeNumber.h	\
	ExtensionORAddressComponents.h	\
	PhysicalDeliveryPersonalName.h	\
	PhysicalDeliveryOrganizationName.h	\
	ExtensionPhysicalDeliveryAddressComponents.h	\
	UnformattedPostalAddress.h	\
	StreetAddress.h	\
	PostOfficeBoxAddress.h	\
	PosteRestanteAddress.h	\
	UniquePostalName.h	\
	LocalPostalAttributes.h	\
	PDSParameter.h	\
	ExtendedNetworkAddress.h	\
	PresentationAddress.h	\
	TerminalType.h	\
	TeletexDomainDefinedAttributes.h	\
	TeletexDomainDefinedAttribute.h	\
	SVSVersion.h	\
	ReqType.h	\
	ExportCertReq.h	\
	ExportCertResp.h	\
	ParseCertReq.h	\
	ParseCertResp.h	\
	ValidateCertReq.h	\
	ValidateCertResp.h	\
	SignDataReq.h	\
	SignDataResp.h	\
	VerifySignedDataReq.h	\
	VerifySignedDataResp.h	\
	SignDataInitReq.h	\
	SignDataInitResp.h	\
	SignDataUpdateReq.h	\
	SignDataUpdateResp.h	\
	SignDataFinalReq.h	\
	SignDataFinalResp.h	\
	VerifySignedDataInitReq.h	\
	VerifySignedDataInitResp.h	\
	VerifySignedDataUpdateReq.h	\
	VerifySignedDataUpdateResp.h	\
	VerifySignedDataFinalReq.h	\
	VerifySignedDataFinalResp.h	\
	SignMessageReq.h	\
	SignMessageResp.h	\
	VerifySignedMessageReq.h	\
	VerifySignedMessageResp.h	\
	SignMessageInitReq.h	\
	SignMessageInitResp.h	\
	SignMessageUpdateReq.h	\
	SignMessageUpdateResp.h	\
	SignMessageFinalReq.h	\
	SignMessageFinalResp.h	\
	VerifySignedMessageInitReq.h	\
	VerifySignedMessageInitResp.h	\
	VerifySignedMessageUpdateReq.h	\
	VerifySignedMessageUpdateResp.h	\
	VerifySignedMessageFinalReq.h	\
	VerifySignedMessageFinalResp.h	\
	SetCertTrustListReq.h	\
	GetCertTrustListAltNamesReq.h	\
	GetCertTrustListReq.h	\
	DelCertTrustListReq.h	\
	InitCertAppPolicyReq.h	\
	GetServerCertificateReq.h	\
	GenRandomReq.h	\
	GetCertInfoByOidReq.h	\
	EncryptDataReq.h	\
	DecryptDataReq.h	\
	CreateTimeStampRequestReq.h	\
	CreateTimeStampResponseReq.h	\
	VerifyTimeStampReq.h	\
	GetTimeStampInfoReq.h	\
	SetCertTrustListResp.h	\
	GetCertTrustListAltNamesResp.h	\
	GetCertTrustListResp.h	\
	DelCertTrustListResp.h	\
	InitCertAppPolicyResp.h	\
	GetServerCertificateResp.h	\
	GenRandomResp.h	\
	GetCertInfoByOidResp.h	\
	EncryptDataResp.h	\
	DecryptDataResp.h	\
	CreateTimeStampRequestResp.h	\
	CreateTimeStampResponseResp.h	\
	VerifyTimeStampResp.h	\
	GetTimeStampInfoResp.h	\
	Request.h	\
	SVSRequest.h	\
	RespStatus.h	\
	RespType.h	\
	Respond.h	\
	SVSRespond.h	\
	TimeStampReq.h	\
	MessageImprint.h	\
	TSAPolicyId.h	\
	TimeStampResq.h	\
	PKIStatusInfo.h	\
	PKIStatus.h	\
	PKIFreeText.h	\
	PKIFailureInfo.h	\
	TimeStampToken.h	\
	ContentInfo.h	\
	ContentType.h	\
	EnvelopedData.h	\
	EncryptedContentInfo.h	\
	EncryptedContent.h	\
	RecipientInfos.h	\
	RecipientInfo.h	\
	IssuerAndSerialNumber.h	\
	ContentEncryptionAlgorithmIdentifier.h	\
	KeyEncryptionAlgorithmIdentifier.h	\
	SM2Cipher.h	\
	SM2Signature.h	\
	SignedData.h	\
	DigestAlgorithmIdentifiers.h	\
	DigestAlgorithmIdentifier.h	\
	ExtendedCertificatesAndCertificates.h	\
	ExtendedCertificateOrCertificate.h	\
	ExtendedCertificate.h	\
	ExtendedCertificateInfo.h	\
	Attributes.h	\
	SignatureAlgorithmIdentifier.h	\
	Signature.h	\
	CertificateRevocationLists.h	\
	CertificateRevocationList.h	\
	SignerInfos.h	\
	SignerInfo.h	\
	DigestEncryptionAlgorithmIdentifier.h	\
	EncryptedEDigest.h	\
	SigningCertificateV2.h	\
	PolicyInformation.h	\
	CertPolicyId.h	\
	PolicyQualifierInfo.h	\
	PolicyQualifierId.h	\
	ESSCertIDv2.h	\
	Hash.h	\
	IssuerSerial.h	\
	GeneralNames.h	\
	GeneralName.h	\
	AnotherName.h	\
	EDIPartyName.h	\
	SigningCertificate.h	\
	ESSCertID.h

ASN_MODULE_HEADERS+=ANY.h
ASN_MODULE_SOURCES+=ANY.c
ASN_MODULE_HEADERS+=BMPString.h
ASN_MODULE_SOURCES+=BMPString.c
ASN_MODULE_HEADERS+=UTF8String.h
ASN_MODULE_HEADERS+=BOOLEAN.h
ASN_MODULE_SOURCES+=BOOLEAN.c
ASN_MODULE_HEADERS+=INTEGER.h
ASN_MODULE_HEADERS+=NativeEnumerated.h
ASN_MODULE_HEADERS+=GeneralizedTime.h
ASN_MODULE_SOURCES+=GeneralizedTime.c
ASN_MODULE_HEADERS+=IA5String.h
ASN_MODULE_SOURCES+=IA5String.c
ASN_MODULE_SOURCES+=INTEGER.c
ASN_MODULE_SOURCES+=NativeEnumerated.c
ASN_MODULE_HEADERS+=NativeInteger.h
ASN_MODULE_SOURCES+=NativeInteger.c
ASN_MODULE_HEADERS+=NumericString.h
ASN_MODULE_SOURCES+=NumericString.c
ASN_MODULE_HEADERS+=OBJECT_IDENTIFIER.h
ASN_MODULE_SOURCES+=OBJECT_IDENTIFIER.c
ASN_MODULE_HEADERS+=PrintableString.h
ASN_MODULE_SOURCES+=PrintableString.c
ASN_MODULE_HEADERS+=TeletexString.h
ASN_MODULE_SOURCES+=TeletexString.c
ASN_MODULE_HEADERS+=UTCTime.h
ASN_MODULE_SOURCES+=UTCTime.c
ASN_MODULE_SOURCES+=UTF8String.c
ASN_MODULE_HEADERS+=UniversalString.h
ASN_MODULE_SOURCES+=UniversalString.c
ASN_MODULE_HEADERS+=asn_SEQUENCE_OF.h
ASN_MODULE_SOURCES+=asn_SEQUENCE_OF.c
ASN_MODULE_HEADERS+=asn_SET_OF.h
ASN_MODULE_SOURCES+=asn_SET_OF.c
ASN_MODULE_HEADERS+=constr_CHOICE.h
ASN_MODULE_SOURCES+=constr_CHOICE.c
ASN_MODULE_HEADERS+=constr_SEQUENCE.h
ASN_MODULE_SOURCES+=constr_SEQUENCE.c
ASN_MODULE_HEADERS+=constr_SEQUENCE_OF.h
ASN_MODULE_SOURCES+=constr_SEQUENCE_OF.c
ASN_MODULE_HEADERS+=constr_SET_OF.h
ASN_MODULE_HEADERS+=constr_SET.h
ASN_MODULE_SOURCES+=constr_SET.c
ASN_MODULE_SOURCES+=constr_SET_OF.c
ASN_MODULE_HEADERS+=asn_application.h
ASN_MODULE_HEADERS+=asn_system.h
ASN_MODULE_HEADERS+=asn_codecs.h
ASN_MODULE_HEADERS+=asn_internal.h
ASN_MODULE_HEADERS+=OCTET_STRING.h
ASN_MODULE_SOURCES+=OCTET_STRING.c
ASN_MODULE_HEADERS+=BIT_STRING.h
ASN_MODULE_SOURCES+=BIT_STRING.c
ASN_MODULE_SOURCES+=asn_codecs_prim.c
ASN_MODULE_HEADERS+=asn_codecs_prim.h
ASN_MODULE_HEADERS+=ber_tlv_length.h
ASN_MODULE_SOURCES+=ber_tlv_length.c
ASN_MODULE_HEADERS+=ber_tlv_tag.h
ASN_MODULE_SOURCES+=ber_tlv_tag.c
ASN_MODULE_HEADERS+=ber_decoder.h
ASN_MODULE_SOURCES+=ber_decoder.c
ASN_MODULE_HEADERS+=der_encoder.h
ASN_MODULE_SOURCES+=der_encoder.c
ASN_MODULE_HEADERS+=constr_TYPE.h
ASN_MODULE_SOURCES+=constr_TYPE.c
ASN_MODULE_HEADERS+=constraints.h
ASN_MODULE_SOURCES+=constraints.c
ASN_MODULE_HEADERS+=xer_support.h
ASN_MODULE_SOURCES+=xer_support.c
ASN_MODULE_HEADERS+=xer_decoder.h
ASN_MODULE_SOURCES+=xer_decoder.c
ASN_MODULE_HEADERS+=xer_encoder.h
ASN_MODULE_SOURCES+=xer_encoder.c
ASN_MODULE_HEADERS+=per_support.h
ASN_MODULE_SOURCES+=per_support.c
ASN_MODULE_HEADERS+=per_decoder.h
ASN_MODULE_SOURCES+=per_decoder.c
ASN_MODULE_HEADERS+=per_encoder.h
ASN_MODULE_SOURCES+=per_encoder.c
ASN_MODULE_HEADERS+=per_opentype.h
ASN_MODULE_SOURCES+=per_opentype.c
#ASN_CONVERTER_SOURCES+=converter-sample.c

lib_LTLIBRARIES=libsomething.la
libsomething_la_SOURCES=$(ASN_MODULE_SOURCES) $(ASN_MODULE_HEADERS)

# This file may be used as an input for make(3)
# Remove the lines below to convert it into a pure .am file
TARGET = progname
CLIENT = client
SERVER = server
CFLAGS += -I. -I/root/zed/SVS/include -I/opt/svs/dependency/lib/include/ -I/opt/ldap/include -I/opt/svs/db/mysql/include/
#OBJS=${ASN_MODULE_SOURCES:.c=.o} ${ASN_CONVERTER_SOURCES:.c=.o}
OBJS=${ASN_MODULE_SOURCES:.c=.o} main.o util.o
CLTS=${ASN_MODULE_SOURCES:.c=.o} client.o
SRVS=${ASN_MODULE_SOURCES:.c=.o} server.o util.o

all: $(TARGET) $(CLIENT) $(SERVER)

$(TARGET): ${OBJS}
	$(CC) $(CFLAGS) -o $(TARGET) ${OBJS} $(LDFLAGS) $(LIBS)
$(CLIENT): ${CLTS}
	$(CC) $(CFLAGS) -o $(CLIENT) ${CLTS} /opt/svs/dependency/lib/libbase64.so -lpthread -L/opt/svs/dependency/lib/ -lMidSign_ib 
$(SERVER): ${SRVS}
	$(CC) -o $(SERVER) ${SRVS} /opt/svs/dependency/lib/libcrypto.so.0.9.8.ib /opt/svs/dependency/lib/libbase64.so /opt/svs/dependency/lib/libfmapiv100.so -L/opt/svs/dependency/lib/ -lMidSign_ib -levent_core -levent_pthreads -lldap -L/opt/svs/db/mysql/lib/ -lmysqlclient -lpthread


.SUFFIXES:
.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET) $(CLIENT) $(SERVER)
	rm -f $(OBJS) client.o server.o

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	/root/zed/bin/asn1c -fbless-SIZE svs.asn
