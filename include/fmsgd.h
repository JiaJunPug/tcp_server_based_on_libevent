
#ifndef _FM_SGD_H_
#define _FM_SGD_H_ 1

#ifdef __cplusplus
	extern "C"{
#endif

//�Գ��㷨��ʶ
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_SM4_ECB		0x00000401
#define SGD_SM4_CBC		0x00000402
#define SGD_SM4_CFB		0x00000404
#define SGD_SM4_OFB		0x00000408
#define SGD_SM4_MAC		0x00000410

#define SGD_DES_ECB		0x00001001
#define SGD_DES_CBC		0x00001002
#define SGD_DES_CFB		0x00001004
#define SGD_DES_OFB		0x00001008
#define SGD_DES_MAC		0x00001010
#define SGD_DES_CTR		0x00001020

#define SGD_3DES_ECB	0x00002001
#define SGD_3DES_CBC	0x00002002
#define SGD_3DES_CFB	0x00002004
#define SGD_3DES_OFB	0x00002008
#define SGD_3DES_MAC	0x00002010
#define SGD_3DES_CTR	0x00002020

#define SGD_AES_ECB		0x00004001
#define SGD_AES_CBC		0x00004002
#define SGD_AES_CFB		0x00004004
#define SGD_AES_OFB		0x00004008
#define SGD_AES_MAC		0x00004010

//�ǶԳ��㷨��ʶ
#define SGD_RSA			0x00010000
#define SGD_RSA_SIGN	0x00010100
#define SGD_RSA_ENC		0x00010200
#define SGD_SM2			0x00020100
#define SGD_SM2_1		0x00020200
#define SGD_SM2_2		0x00020400
#define SGD_SM2_3		0x00020800

#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
#define SGD_SHA384		0x00000008
#define SGD_SHA512		0x00000010
#define SGD_SHA224		0x00000020
#define SGD_MD5			0x00000040

//�����붨��
#define SDR_OK						0x0						//�����ɹ�
#define SDR_BASE					0x01000000				//���������ֵ
#define SDR_UNKNOWERR				SDR_BASE + 0x00000001	//δ֪����
#define SDR_NOTSUPPORT				SDR_BASE + 0x00000002	//��֧�ֵĽӿڵ���
#define SDR_COMMFAIL				SDR_BASE + 0x00000003	//���豸ͨ��ʧ��
#define SDR_HARDFAIL				SDR_BASE + 0x00000004	//����ģ������Ӧ
#define SDR_OPENDEVICE				SDR_BASE + 0x00000005	//���豸ʧ��
#define SDR_OPENSESSION				SDR_BASE + 0x00000006	//�����Ựʧ��
#define SDR_PARDENY					SDR_BASE + 0x00000007	//��˽Կʹ��Ȩ��
#define SDR_KEYNOTEXIST				SDR_BASE + 0x00000008	//�����ڵ���Կ����
#define SDR_ALGNOTSUPPORT			SDR_BASE + 0x00000009	//��֧�ֵ��㷨����
#define SDR_ALGMODNOTSUPPORT		SDR_BASE + 0x0000000A	//��֧�ֵ��㷨ģʽ����
#define SDR_PKOPERR					SDR_BASE + 0x0000000B	//��Կ����ʧ��
#define SDR_SKOPERR					SDR_BASE + 0x0000000C	//˽Կ����ʧ��
#define SDR_SIGNERR					SDR_BASE + 0x0000000D	//ǩ������ʧ��
#define SDR_VERIFYERR				SDR_BASE + 0x0000000E	//��֤ǩ��ʧ��
#define SDR_SYMOPERR				SDR_BASE + 0x0000000F	//�Գ��㷨����ʧ��
#define SDR_STEPERR					SDR_BASE + 0x00000010	//�ಽ���㲽�����
#define SDR_FILESIZEERR				SDR_BASE + 0x00000011	//�ļ����ȳ�������
#define SDR_FILENOEXIST				SDR_BASE + 0x00000012	//ָ�����ļ�������
#define SDR_FILEOFSERR				SDR_BASE + 0x00000013	//�ļ���ʼλ�ô���
#define SDR_KEYTYPEERR				SDR_BASE + 0x00000014	//��Կ���ʹ���
#define SDR_KEYERR					SDR_BASE + 0x00000015	//��Կ����


/*�Զ�������*/
#define SDR_NOMANAGEMENTAUTH	SDR_BASE + 0x00000016	//����Ȩ�޲�����
#define SDR_NOOPERATIONAUTH		SDR_BASE + 0x00000017	//����Ȩ�޲�����
#define SDR_MALLOCERR			SDR_BASE + 0x00000018	//�ڴ�������
#define SDR_HANDLENULL			SDR_BASE + 0x00000019	//���Ϊ��
#define SDR_PARAMETERSERR		SDR_BASE + 0x00000020	//��������
#define SDR_DEVICEERR			SDR_BASE + 0x00000021	//�����豸��������
#define SDR_CREATEFILEERR		SDR_BASE + 0x00000022	//�����ļ�ʧ��
#define SDR_PRIVATEERR			SDR_BASE + 0x00000023	//˽ԿȨ�������
#define SDR_LENGTH_ERROR        SDR_BASE + 0x00000024   //����ĳ��ȴ���
#define SDR_INDEX_ERROR         SDR_BASE + 0x00000025   //��Կ��������
#define SDR_KEYLENGTHERROR      SDR_BASE + 0x00000026   //��Կ���ȴ���

/************************�豸��Ϣ�ṹ**************************************/
typedef struct DeviceInfo_st
{
	unsigned char IssuerName[40];		//�豸������������
	unsigned char DeviceName[16];		//�豸�ͺ�
	unsigned char DeviceSerial[16];		//�豸��ţ����������ڣ�8�ַ��������κţ�3�ַ�������ˮ�ţ�5�ַ���
	unsigned int  DeviceVersion;		//�����豸�ڲ������İ汾��
	unsigned int  StandardVersion;		//�����豸֧�ֵĽӿڹ淶�汾��
	unsigned int  AsymAlgAbility[2];	//ǰ4�ֽڱ�ʾ֧�ֵ��㷨,��ʾ����Ϊ�ǶԳ��㷨��ʶ��λ��Ľ��
	unsigned int  SymAlgAbility;		//����֧�ֵĶԳ��㷨����ʾ����Ϊ�Գ��㷨��ʶ��λ��������
	unsigned int  HashAlgAbility;		//����֧�ֵ��Ӵ��㷨����ʾ����Ϊ�Ӵ��㷨��ʶ��λ��������
	unsigned int  BufferSize;			//֧�ֵ�����ļ��洢�ռ䣨��λ�ֽڣ�
}DEVICEINFO;


/*********************************RSA��Կ�ṹ*******************************/
#define LiteRSAref_MAX_BITS    2048
#define LiteRSAref_MAX_LEN     ((LiteRSAref_MAX_BITS + 7) / 8)
#define LiteRSAref_MAX_PBITS   ((LiteRSAref_MAX_BITS + 1) / 2)
#define LiteRSAref_MAX_PLEN    ((LiteRSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKeyLite_st
{
	unsigned int  bits;
	unsigned char m[LiteRSAref_MAX_LEN];
	unsigned char e[LiteRSAref_MAX_LEN];
}RSArefPublicKeyLite;

typedef struct RSArefPrivateKeyLite_st
{
	unsigned int  bits;
	unsigned char m[LiteRSAref_MAX_LEN];
	unsigned char e[LiteRSAref_MAX_LEN];
	unsigned char d[LiteRSAref_MAX_LEN];
	unsigned char prime[2][LiteRSAref_MAX_PLEN];
	unsigned char pexp[2][LiteRSAref_MAX_PLEN];
	unsigned char coef[LiteRSAref_MAX_PLEN];
}RSArefPrivateKeyLite;

#define ExRSAref_MAX_BITS    4096
#define ExRSAref_MAX_LEN     ((ExRSAref_MAX_BITS + 7) / 8)
#define ExRSAref_MAX_PBITS   ((ExRSAref_MAX_BITS + 1) / 2)
#define ExRSAref_MAX_PLEN    ((ExRSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKeyEx_st
{
	unsigned int  bits;
	unsigned char m[ExRSAref_MAX_LEN];
	unsigned char e[ExRSAref_MAX_LEN];
} RSArefPublicKeyEx;

typedef struct RSArefPrivateKeyEx_st
{
	unsigned int  bits;
	unsigned char m[ExRSAref_MAX_LEN];
	unsigned char e[ExRSAref_MAX_LEN];
	unsigned char d[ExRSAref_MAX_LEN];
	unsigned char prime[2][ExRSAref_MAX_PLEN];
	unsigned char pexp[2][ExRSAref_MAX_PLEN];
	unsigned char coef[ExRSAref_MAX_PLEN];
} RSArefPrivateKeyEx;

#if defined(SGD_RSA_MAX_BITS) && (SGD_RSA_MAX_BITS > LiteRSAref_MAX_BITS)
#define RSAref_MAX_BITS    ExRSAref_MAX_BITS
#define RSAref_MAX_LEN     ExRSAref_MAX_LEN
#define RSAref_MAX_PBITS   ExRSAref_MAX_PBITS
#define RSAref_MAX_PLEN    ExRSAref_MAX_PLEN

typedef struct RSArefPublicKeyEx_st  RSArefPublicKey;
typedef struct RSArefPrivateKeyEx_st  RSArefPrivateKey;
#else
#define RSAref_MAX_BITS    LiteRSAref_MAX_BITS
#define RSAref_MAX_LEN     LiteRSAref_MAX_LEN
#define RSAref_MAX_PBITS   LiteRSAref_MAX_PBITS
#define RSAref_MAX_PLEN    LiteRSAref_MAX_PLEN

typedef struct RSArefPublicKeyLite_st  RSArefPublicKey;
typedef struct RSArefPrivateKeyLite_st  RSArefPrivateKey;
#endif

#define ECCMAXBITS256
/******************************ECC��Կ�ṹ********************************/
#ifdef ECCMAXBITS256
#define ECCref_MAX_BITS			256 
#else
#define ECCref_MAX_BITS			512 
#endif
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;					//ģ��
	unsigned char x[ECCref_MAX_LEN]; 	//��Կx����
	unsigned char y[ECCref_MAX_LEN]; 	//��Կy����
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int  bits;				//ģ��
    unsigned char D[ECCref_MAX_LEN];//˽Կ
} ECCrefPrivateKey;


/*****************************ECC ���Ľṹ********************************/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN]; //��y�����Բ�����ϵĵ㣨x��y��
	unsigned char y[ECCref_MAX_LEN]; //��x�����Բ�����ϵĵ㣨x��y��
	unsigned char M[32]; //Ԥ��������֧�ִ�MAC�����ECC�㷨
	unsigned int  L;				 //�������ݳ���
	unsigned char C[136];			 //��������
}ECCCipher;


/****************************ECC ǩ���ṹ*********************************/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];	//ǩ����r����
	unsigned char s[ECCref_MAX_LEN];	//ǩ����s����
} ECCSignature;

/******************ECC������Կ�Ա����ṹ**********************************/
typedef struct SDF_ENVELOPEDKEYBLOB
{
	unsigned long ulAsymmAlgID;
	unsigned long ulSymmAlgID;
	ECCCipher	  ECCCipherBlob;
	ECCrefPublicKey PubKey;
	unsigned char  cbEncryptedPriKey[64];
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/*************************************************************************/

/*
#define USER_KEY_START_INDEX  2
#define USER_KEY_END_INDEX    61
#define ENCRYPT_USER_KEY      63

#define UserKeyINDEX(i)   if(((2*i)<USER_KEY_START_INDEX)||((2*i+1)>USER_KEY_END_INDEX))\
								return SDR_INDEX_ERROR;
							
#define EncryptUserKey(i)  if(i<1||i>ENCRYPT_USER_KEY)\
							return SDR_INDEX_ERROR;	
*/
#define UserKeyINDEX_RSA(i)   if(RSAKeyIndexCheck(i) == -1)\
							return SDR_INDEX_ERROR;

#define UserKeyINDEX_ECC(i)   if(ECCKeyIndexCheck(i) == -1)\
							return SDR_INDEX_ERROR;

#define EncryptUserKey(i)  if(SYMKeyIndexCheck(i) == -1)\
							return SDR_INDEX_ERROR;	


/********************************�豸�����ຯ��**************************/
/*
ԭ�ͣ�	int SDF_OpenDevice(void **phDeviceHandle);
������	�������豸
������	phDeviceHandle[out]	�����豸���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	phDeviceHandle�ɺ�����ʼ������д����
*/
int SDF_OpenDevice(void **phDeviceHandle);

/*
6.1.1 ���豸����ָ�������ļ�·����
ԭ�ͣ�
int SDF_OpenDeviceWithPath(
char * pcCfgPath,
unsigned int phDeviceHandle);
������ �������豸
������
pcCfgPath[in]
�����ļ�����Ŀ¼�������������ļ����ƣ������ļ�
����Ϊswsds.ini��
�磺/etc/swhsm/
phDeviceHandle[out] �����豸���
����ֵ�� 0 �ɹ�
��0 ʧ�ܣ����ش������
��ע�� phDeviceHandle �ɺ�����ʼ������д����
*/
int SDF_OpenDeviceWithPath(char * pcCfgPath, void **phDeviceHandle);

/*
ԭ�ͣ�
int SDF_OpenDeviceWithParameter(
unsigned int phDeviceHandle,
char **argv);
������ �������豸
������ phDeviceHandle[out] �����豸���
Argv[in]
����ֵ�� 0 �ɹ�
��0 ʧ�ܣ����ش������
��ע�� phDeviceHandle �ɺ�����ʼ������д����
*/
int SDF_OpenDeviceWithParameter(void **phDeviceHandle, char **argv);

/*
ԭ�ͣ�	int SDF_CloseDevice(void *hDeviceHandle);
������	�ر������豸�����ͷ������Դ
������	hDeviceHandle[in]	�Ѵ򿪵��豸���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_CloseDevice(void *hDeviceHandle);

/*
ԭ�ͣ�	int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
������	�����������豸�ĻỰ
������	hDeviceHandle[in]	�Ѵ򿪵��豸���
	phSessionHandle[out]	�����������豸�������»Ự���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);

/*
ԭ�ͣ�	int SDF_CloseSession(void *hSessionHandle);
������	�ر��������豸�ѽ����ĻỰ�����ͷ������Դ
������	hSessionHandle [in]	�������豸�ѽ����ĻỰ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_CloseSession(void *hSessionHandle);

/*
ԭ�ͣ�	int SDF_GetDeviceInfo (
void *hSessionHandle,
DEVICEINFO *pstDeviceInfo);
������	��ȡ�����豸��������
������	hSessionHandle[in]	���豸�����ĻỰ���
	pstDeviceInfo [out]	�豸����������Ϣ�����ݼ���ʽ���豸��Ϣ����

����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_GetDeviceInfo (void *hSessionHandle,DEVICEINFO *pstDeviceInfo);

/*
ԭ�ͣ�	int SDF_GenerateRandom (
void *hSessionHandle, 
unsigned int  uiLength,
unsigned char *pucRandom);
������	��ȡָ�����ȵ������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiLength[in]	����ȡ�����������
	pucRandom[out]	������ָ�룬���ڴ�Ż�ȡ�������
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_GenerateRandom 
(
	void *hSessionHandle, 
	unsigned int  uiLength, 
	unsigned char *pucRandom
);

/*
������	��ȡ�����豸�ڲ��洢��ָ������˽Կ��ʹ��Ȩ
������	hSessionHandle[in]
	uiKeyIndex[in]
	pucPassword[in]
	uiPwdLength[in]
����ֵ��	0
	��0
��ע��	���淶�漰�����豸�洢����Կ������ֵ�ĵ���ʼ����ֵΪ1�����Ϊn�������豸��ʵ�ʴ洢��������nֵ
*/
int SDF_GetPrivateKeyAccessRight 
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex, 
	unsigned char *pucPassword, 
	unsigned int  uiPwdLength
);

/*
ԭ�ͣ�	int SDF_ReleasePrivateKeyAccessRight (
void *hSessionHandle, 
unsigned int  uiKeyIndex);
������	�ͷ������豸�洢��ָ������˽Կ��ʹ����Ȩ
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢˽Կ����ֵ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ReleasePrivateKeyAccessRight (void *hSessionHandle, unsigned int  uiKeyIndex);


/**********************************��Կ�����ຯ��***********************************/
/*
ԭ�ͣ�	int SDF_ExportSignPublicKey_RSA(
void *hSessionHandle, 
unsigned int  uiKeyIndex,
RSArefPublicKey *pucPublicKey);
������	���������豸�ڲ��洢��ָ������λ�õ�ǩ����Կ
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢��RSA��Կ������ֵ
	pucPublicKey[out]	RSA��Կ�ṹ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExportSignPublicKey_RSA
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex, 
	RSArefPublicKey *pucPublicKey
);

/*
ԭ�ͣ�	int SDF_ExportEncPublicKey_RSA(
void *hSessionHandle, 
unsigned int  uiKeyIndex,
RSArefPublicKey *pucPublicKey);
������	���������豸�ڲ��洢��ָ������λ�õļ��ܹ�Կ
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢��RSA��Կ������ֵ
	pucPublicKey[out]	RSA��Կ�ṹ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExportEncPublicKey_RSA
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex, 
	RSArefPublicKey *pucPublicKey
);

/*
ԭ�ͣ�	int SDF_GenerateKeyPair_RSA(
void *hSessionHandle, 
unsigned int  uiKeyBits,
RSArefPublicKey *pucPublicKey,
RSArefPrivateKey *pucPrivateKey);
������	���������豸����ָ��ģ����RSA��Կ��
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyBits [in]	ָ����Կģ��
	pucPublicKey[out]	RSA��Կ�ṹ
	pucPrivateKey[out]	RSA˽Կ�ṹ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_GenerateKeyPair_RSA
(
	void *hSessionHandle, 
	unsigned int  uiKeyBits, 
	RSArefPublicKey *pucPublicKey, 
	RSArefPrivateKey *pucPrivateKey
);

/*
ԭ�ͣ�	int SDF_GenerateKeyWithIPK_RSA (
void *hSessionHandle, 
unsigned int uiIPKIndex,
unsigned int uiKeyBits,
unsigned char *pucKey,
unsigned int *puiKeyLength,
void **phKeyHandle);
������	���ɻỰ��Կ����ָ���������ڲ����ܹ�Կ���������ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiIPKIndex[in]	�����豸�ڲ��洢��Կ������ֵ
	uiKeyBits[in]	ָ�������ĻỰ��Կ����
	pucKey[out]	������ָ�룬���ڴ�ŷ��ص���Կ����
	puiKeyLength[out]	���ص���Կ���ĳ���
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��Կ��������ʱ��䷽ʽ����PKCS#1 v1.5��Ҫ����У����ص���Կ������IV���֡�
*/
int SDF_GenerateKeyWithIPK_RSA 
(
	void *hSessionHandle, 
	unsigned int uiIPKIndex, 
	unsigned int uiKeyBits, 
	unsigned char *pucKey, 
	unsigned int *puiKeyLength, 
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_GenerateKeyWithEPK_RSA (
void *hSessionHandle, 
unsigned int uiKeyBits,
RSArefPublicKey *pucPublicKey,
unsigned char *pucKey,
unsigned int *puiKeyLength,
void **phKeyHandle);
������	���ɻỰ��Կ�����ⲿ��Կ���������ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyBits[in]	ָ�������ĻỰ��Կ����
	pucPublicKey[in]	������ⲿRSA��Կ�ṹ
	pucKey[out]	������ָ�룬���ڴ�ŷ��ص���Կ����
	puiKeyLength[out]	���ص���Կ���ĳ���
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��Կ��������ʱ��䷽ʽ����PKCS#1 v1.5��Ҫ����У����ص���Կ������IV���֡�
*/
int SDF_GenerateKeyWithEPK_RSA 
(
	void *hSessionHandle, 
	unsigned int uiKeyBits, 
	RSArefPublicKey *pucPublicKey, 
	unsigned char *pucKey, 
	unsigned int *puiKeyLength, 
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_ImportKeyWithISK_RSA (
void *hSessionHandle, 
unsigned int uiISKIndex,
unsigned char *pucKey,
unsigned int *puiKeyLength,
void **phKeyHandle);
������	����Ự��Կ�����ڲ�˽Կ���ܣ�ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiISKIndex[in]	�����豸�ڲ��洢����˽Կ������ֵ����Ӧ�ڼ���ʱ�Ĺ�Կ
	pucKey[in]	������ָ�룬���ڴ���������Կ����
	puiKeyLength[in]	�������Կ���ĳ���
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��䷽ʽ�빫Կ����ʱ��ͬ��
*/
int SDF_ImportKeyWithISK_RSA 
(
	void *hSessionHandle, 
	unsigned int uiISKIndex, 
	unsigned char *pucKey, 
	unsigned int uiKeyLength, 
	void **phKeyHandle
);

/*
	int SDF_ExchangeDigitEnvelopeBaseOnRSA(
void *hSessionHandle, 
unsigned int  uiKeyIndex,
RSArefPublicKey *pucPublicKey,
unsigned char *pucDEInput,
unsigned int  uiDELength,
unsigned char *pucDEOutput,
unsigned int  *puiDELength);
������	�����ڲ����ܹ�Կ���ܵĻỰ��Կת��Ϊ���ⲿָ���Ĺ�Կ���ܣ������������ŷ�ת����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢���ڲ�RSA��Կ������ֵ
	pucPublicKey [in]	�ⲿRSA��Կ�ṹ
	pucDEInput [in]	������ָ�룬���ڴ������ĻỰ��Կ����
	uiDELength[in]	����ĻỰ��Կ���ĳ���
	pucDEOutput[out]	������ָ�룬���ڴ������ĻỰ��Կ����
	puiDELength[out]	����ĻỰ��Կ���ĳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExchangeDigitEnvelopeBaseOnRSA
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex, 
	RSArefPublicKey *pucPublicKey, 
	unsigned char *pucDEInput, 
	unsigned int  uiDELength, 
	unsigned char *pucDEOutput, 
	unsigned int  *puiDELength
);

/*
	int SDF_ExportSignPublicKey_ECC(
void *hSessionHandle, 
unsigned int  uiKeyIndex,
ECCrefPublicKey *pucPublicKey);
������	���������豸�ڲ��洢��ָ������λ�õ�ǩ����Կ
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢��ECC��Կ������ֵ
	pucPublicKey[out]	ECC��Կ�ṹ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExportSignPublicKey_ECC
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex,
	ECCrefPublicKey *pucPublicKey
);

/*
ԭ�ͣ�	int SDF_ExportEncPublicKey_ECC(
void *hSessionHandle, 
unsigned int  uiKeyIndex,
ECCrefPublicKey *pucPublicKey);
������	���������豸�ڲ��洢��ָ������λ�õļ��ܹ�Կ
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢��ECC��Կ������ֵ
	pucPublicKey[out]	ECC��Կ�ṹ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExportEncPublicKey_ECC
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex,
	ECCrefPublicKey *pucPublicKey
);

/*
ԭ�ͣ�	int SDF_GenerateKeyPair_ECC(
void *hSessionHandle, 
unsigned int  uiAlgID,
unsigned int  uiKeyBits,
ECCrefPublicKey *pucPublicKey,
ECCrefPrivateKey *pucPrivateKey);
������	���������豸����ָ�����ͺ�ģ����ECC��Կ��
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	ָ���㷨��ʶ
	uiKeyBits [in]	ָ����Կ����
	pucPublicKey[out]	ECC��Կ�ṹ
	pucPrivateKey[out]	ECC˽Կ�ṹ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_GenerateKeyPair_ECC
(
	void *hSessionHandle, 
	unsigned int  uiAlgID,
	unsigned int  uiKeyBits,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey
);

/*
ԭ�ͣ�	int SDF_GenerateKeyWithIPK_ECC (
void *hSessionHandle, 
unsigned int uiIPKIndex,
unsigned int uiKeyBits,
ECCCipher *pucKey,
void **phKeyHandle);
������	���ɻỰ��Կ����ָ���������ڲ�ECC���ܹ�Կ���������ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiIPKIndex[in]	�����豸�ڲ��洢��Կ������ֵ
	uiKeyBits[in]	ָ�������ĻỰ��Կ����
	pucKey[out]	������ָ�룬���ڴ�ŷ��ص���Կ����
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	���ص���Կ������IV���֡�
*/
int SDF_GenerateKeyWithIPK_ECC 
(
	void *hSessionHandle, 
	unsigned int uiIPKIndex,
	unsigned int uiKeyBits,
	ECCCipher *pucKey,
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_GenerateKeyWithEPK_ECC (
void *hSessionHandle, 
unsigned int uiKeyBits,
unsigned int  uiAlgID,
ECCrefPublicKey *pucPublicKey,
ECCCipher *pucKey,
void **phKeyHandle);
������	���ɻỰ��Կ�����ⲿECC��Կ���������ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyBits[in]	ָ�������ĻỰ��Կ����
	uiAlgID[in]	�ⲿECC��Կ���㷨��ʶ
	pucPublicKey[in]	������ⲿECC��Կ�ṹ
	pucKey[out]	������ָ�룬���ڴ�ŷ��ص���Կ����
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	���ص���Կ������IV���֡�
*/
int SDF_GenerateKeyWithEPK_ECC 
(
	void *hSessionHandle, 
	unsigned int uiKeyBits,
	unsigned int  uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucKey,
	void **phKeyHandle
);


/*
ԭ�ͣ�	int SDF_ImportKeyWithISK_ECC (
void *hSessionHandle,
unsigned int uiISKIndex,
ECCCipher *pucKey,
void **phKeyHandle);
������	����Ự��Կ�����ڲ�ECC����˽Կ���ܣ�ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiISKIndex[in]	�����豸�ڲ��洢����˽Կ������ֵ����Ӧ�ڼ���ʱ�Ĺ�Կ
	pucKey[in]	������ָ�룬���ڴ���������Կ����
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ImportKeyWithISK_ECC 
(
	void *hSessionHandle,
	unsigned int uiISKIndex,
	ECCCipher *pucKey,
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_GenerateAgreementDataWithECC (
void *hSessionHandle, 
unsigned int uiISKIndex,
unsigned int uiKeyBits,
unsigned char *pucSponsorID,
unsigned int uiSponsorIDLength,
ECCrefPublicKey  *pucSponsorPublicKey,
ECCrefPublicKey  *pucSponsorTmpPublicKey,
void **phAgreementHandle);
������	ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����ͬʱ����ָ������λ�õ�ECC��Կ����ʱECC��Կ�ԵĹ�Կ��Э�̾����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiISKIndex[in]	�����豸�ڲ��洢����˽Կ������ֵ����˽Կ���ڲ�����ԿЭ��
	uiKeyBits[in]	Ҫ��Э�̵���Կ����
	pucSponsorID[in]	������ԿЭ�̵ķ���IDֵ
	uiSponsorIDLength[in]	����ID����
	pucSelfPublicKey[out]	���صķ���ECC��Կ�ṹ
	pucSelfTmpPublicKey[out]	���صķ�����ʱECC��Կ�ṹ
	phAgreementHandle[out]	���ص�Э�̾�������ڼ���Э����Կ
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	ΪЭ�̻Ự��Կ��Э�̵ķ���Ӧ���ȵ��ñ�������
����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ������
*/
int SDF_GenerateAgreementDataWithECC 
(
	void *hSessionHandle, 
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey  *pucSponsorPublicKey,
	ECCrefPublicKey  *pucSponsorTmpPublicKey,
	void **phAgreementHandle
);

/*
ԭ�ͣ�	int SDF_GenerateKeyWithECC (
void *hSessionHandle, 
unsigned char *pucResponseID,
unsigned int uiResponseIDLength��
ECCrefPublicKey *pucResponsePublicKey,
ECCrefPublicKey *pucResponseTmpPublicKey,
void *hAgreementHandle,
void **phKeyHandle);
������	ʹ��ECC��ԿЭ���㷨��ʹ������Э�̾������Ӧ����Э�̲�������Ự��Կ��ͬʱ���ػỰ��Կ�����
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucResponseID[in]	�ⲿ�������Ӧ��IDֵ
	uiResponseIDLength[in]	�ⲿ�������Ӧ��ID����
	pucResponsePublicKey[in]	�ⲿ�������Ӧ��ECC��Կ�ṹ
	pucResponseTmpPublicKey[in]	�ⲿ�������Ӧ����ʱECC��Կ�ṹ
	hAgreementHandle[in]	Э�̾�������ڼ���Э����Կ
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	Э�̵ķ��𷽻����Ӧ����Э�̲�������ñ�����������Ự��Կ��
����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ������
*/
int SDF_GenerateKeyWithECC 
(
	void *hSessionHandle, 
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_GenerateAgreementDataAndKeyWithECC (
void *hSessionHandle, 
unsigned int uiISKIndex,
unsigned int uiKeyBits,
unsigned char *pucResponseID,
unsigned int uiResponseIDLength,
unsigned char *pucSponsorID,
unsigned int uiSponsorIDLength,
ECCrefPublicKey *pucSponsorPublicKey,
ECCrefPublicKey *pucSponsorTmpPublicKey,
ECCrefPublicKey  *pucResponsePublicKey,
ECCrefPublicKey  *pucResponseTmpPublicKey,
void **phKeyHandle);
������	ʹ��ECC��ԿЭ���㷨������Э�̲���������Ự��Կ��ͬʱ���ز�����Э�̲����ͺ���Կ�����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiISKIndex[in]	�����豸�ڲ��洢����˽Կ������ֵ����˽Կ���ڲ�����ԿЭ��
	uiKeyBits[in]	Э�̺�Ҫ���������Կ����
	pucResponseID[in]	��Ӧ��IDֵ
	uiResponseIDLength[in]	��Ӧ��ID����
	pucSponsorID[in]	����IDֵ
	uiSponsorIDLength[in]	����ID����
	pucSponsorPublicKey[in]	�ⲿ����ķ���ECC��Կ�ṹ
	pucSponsorTmpPublicKey[in]	�ⲿ����ķ�����ʱECC��Կ�ṹ
	pucResponsePublicKey[out]	���ص���Ӧ��ECC��Կ�ṹ
	pucResponseTmpPublicKey[out]	���ص���Ӧ����ʱECC��Կ�ṹ
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	����������Ӧ�����á�
����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ����
*/
int SDF_GenerateAgreementDataAndKeyWithECC 
(
	void *hSessionHandle, 
	unsigned int uiISKIndex,
	unsigned int uiKeyBits,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey  *pucResponsePublicKey,
	ECCrefPublicKey  *pucResponseTmpPublicKey,
	void **phKeyHandle
);

/*
	int SDF_ExchangeDigitEnvelopeBaseOnECC(
void *hSessionHandle, 
unsigned int  uiKeyIndex,
unsigned int  uiAlgID,
ECCrefPublicKey *pucPublicKey,
ECCCipher *pucEncDataIn,
ECCCipher *pucEncDataOut);
������	�����ڲ����ܹ�Կ���ܵĻỰ��Կת��Ϊ���ⲿָ���Ĺ�Կ���ܣ������������ŷ�ת����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�洢��ECC��Կ������ֵ
	uiAlgID[in]	�ⲿECC��Կ���㷨��ʶ
	pucPublicKey [in]	�ⲿECC��Կ�ṹ
	pucEncDataIn[in]	������ָ�룬���ڴ������ĻỰ��Կ����
	pucEncDataOut[out]	������ָ�룬���ڴ������ĻỰ��Կ����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExchangeDigitEnvelopeBaseOnECC
(
	void *hSessionHandle, 
	unsigned int  uiKeyIndex,
	unsigned int  uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	ECCCipher *pucEncDataIn,
	ECCCipher *pucEncDataOut
);

/*
ԭ�ͣ�	int SDF_GenerateKeyWithKEK (
void *hSessionHandle, 
unsigned int uiKeyBits,
unsigned int  uiAlgID,
unsigned int uiKEKIndex, 
unsigned char *pucKey, 
unsigned int *puiKeyLength, 
void **phKeyHandle);
������	���ɻỰ��Կ������Կ������Կ���������ͬʱ������Կ�����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyBits[in]	ָ�������ĻỰ��Կ����
	uiAlgID[in]	�㷨��ʶ��ָ���ԳƼ����㷨
	uiKEKIndex[in]	�����豸�ڲ��洢��Կ������Կ������ֵ
	pucKey[out]	������ָ�룬���ڴ�ŷ��ص���Կ����
	puiKeyLength[out]	���ص���Կ���ĳ���
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	����ģʽʹ��ECBģʽ��
*/
int SDF_GenerateKeyWithKEK 
(
	void *hSessionHandle, 
	unsigned int uiKeyBits,
	unsigned int  uiAlgID,
	unsigned int uiKEKIndex, 
	unsigned char *pucKey, 
	unsigned int *puiKeyLength, 
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_ImportKeyWithKEK (
void *hSessionHandle, 
unsigned int  uiAlgID,
unsigned int uiKEKIndex, 
unsigned char *pucKey, 
unsigned int *puiKeyLength, 
void **phKeyHandle);
������	����Ự��Կ������Կ������Կ���ܣ�ͬʱ���ػỰ��Կ�����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	�㷨��ʶ��ָ���ԳƼ����㷨
	uiKEKIndex[in]	�����豸�ڲ��洢��Կ������Կ������ֵ
	pucKey[in]	������ָ�룬���ڴ���������Կ����
	puiKeyLength[in]	�������Կ���ĳ���
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	����ģʽʹ��ECBģʽ��
*/
int SDF_ImportKeyWithKEK 
(
	void *hSessionHandle, 
	unsigned int  uiAlgID,
	unsigned int uiKEKIndex, 
	unsigned char *pucKey, 
	unsigned int puiKeyLength, 
	void **phKeyHandle
);

/*
ԭ�ͣ�
int SDF_InternalEncrypt_ECC(
void *hSessionHandle,
unsigned int uiISKIndex,
unsigned int uiKeyUsage,
unsigned char *pucData,
unsigned int uiDataLength,
ECCSignature *pucSignature);
������ ʹ���ڲ�ECC ��Կ�����ݽ��м�������
������ hSessionHandle[in] ���豸�����ĻỰ���
uiISKIndex [in] �����豸�ڲ��洢��ECC ��Կ������ֵ
uiKeyUsage [in] ָ��ʹ��ǩ����Կ���Ǽ��ܹ�Կ
SGD_SM2_1��ǩ����Կ
SGD_SM2_3�����ܹ�Կ
pucData[in] ������ָ�룬���ڴ���ⲿ���������
uiDataLength[in] ��������ݳ���
pucSignature[in] ������ָ�룬���ڴ�������ǩ��ֵ����
����ֵ�� 0 �ɹ�
��0 ʧ�ܣ����ش������
��ע��
*/
int SDF_InternalEncrypt_ECC
(
	void		  *hSessionHandle,
	unsigned int  uiISKIndex,
	unsigned int  uiKeyUsage,
	unsigned char *pucData,
	unsigned int  uiDataLength,
	ECCCipher	  *pucEncData
);

/*
ԭ�ͣ�
int SDF_InternalDecrypt_ECC(
void *hSessionHandle,
unsigned int uiISKIndex,
unsigned int uiKeyUsage,
unsigned char *pucData,
unsigned int uiDataLength,
ECCSignature *pucSignature);
������ ʹ���ڲ�ECC ˽Կ�����ݽ��н�������
������ hSessionHandle[in] ���豸�����ĻỰ���
uiISKIndex [in] �����豸�ڲ��洢��ECC ˽Կ������ֵ
uiKeyUsage [in] ָ��ʹ��ǩ��˽Կ���Ǽ���˽Կ
SGD_SM2_1��ǩ��˽Կ
SGD_SM2_3������˽Կ
pucData[in] ������ָ�룬���ڴ���ⲿ���������
uiDataLength[in] ��������ݳ���
pucSignature [out] ������ָ�룬���ڴ�������ǩ��ֵ����
����ֵ�� 0 �ɹ�
��0 ʧ�ܣ����ش������
��ע��
*/
int SDF_InternalDecrypt_ECC
(
	void		  *hSessionHandle,
	unsigned int  uiISKIndex,
	unsigned int  uiKeyUsage,
		ECCCipher	  *pucEncData,
	unsigned char *pucData,
	unsigned int  *puiDataLength
);

/*
ԭ�ͣ�	int SDF_ImportKey (
void *hSessionHandle, 
unsigned char *pucKey, 
unsigned int uiKeyLength,
void **phKeyHandle);
������	�������ĻỰ��Կ��ͬʱ������Կ���
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucKey[in]	������ָ�룬���ڴ���������Կ����
	puiKeyLength[in]	�������Կ���ĳ���
	phKeyHandle[out]	���ص���Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ImportKey 
(
	void *hSessionHandle, 
	unsigned char *pucKey, 
	unsigned int uiKeyLength,
	void **phKeyHandle
);

/*
ԭ�ͣ�	int SDF_DestoryKey (
void *hSessionHandle, 
void *hKeyHandle);
������	���ٻỰ��Կ�����ͷ�Ϊ��Կ���������ڴ����Դ��
������	hSessionHandle[in]	���豸�����ĻỰ���
	hKeyHandle[in]	�������Կ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	�ڶԳ��㷨������ɺ�Ӧ���ñ��������ٻỰ��Կ��
*/
int SDF_DestroyKey (void *hSessionHandle, void *hKeyHandle);


/******************************�ǶԳ��������㺯��************************************/

/*
ԭ�ͣ�	int SDF_ExternalPublicKeyOperation_RSA(
void *hSessionHandle, 
RSArefPublicKey *pucPublicKey,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
unsigned char *pucDataOutput,
unsigned int  *puiOutputLength);
������	ָ��ʹ���ⲿ��Կ�����ݽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucPublicKey [in]	�ⲿRSA��Կ�ṹ
	pucDataInput [in]	������ָ�룬���ڴ�����������
	uiInputLength[in]	��������ݳ���
	pucDataOutput[out]	������ָ�룬���ڴ�����������
	puiOutputLength[out]	��������ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	���ݸ�ʽ��Ӧ�ò��װ
*/
int SDF_ExternalPublicKeyOperation_RSA
(
	void *hSessionHandle, 
	RSArefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int  *puiOutputLength
);

/*
ԭ�ͣ�	int SDF_ExternalPrivateKeyOperation_RSA(
void *hSessionHandle, 
RSArefPrivateKey *pucPrivateKey,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
unsigned char *pucDataOutput,
unsigned int  *puiOutputLength);
������	ָ��ʹ���ⲿ˽Կ�����ݽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucPrivateKey [in]	�ⲿRSA˽Կ�ṹ
	pucDataInput [in]	������ָ�룬���ڴ�����������
	uiInputLength [in]	��������ݳ���
	pucDataOutput [out]	������ָ�룬���ڴ�����������
	puiOutputLength [out]	��������ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	���ݸ�ʽ��Ӧ�ò��װ
*/
int SDF_ExternalPrivateKeyOperation_RSA
(
	void *hSessionHandle, 
	RSArefPrivateKey *pucPrivateKey,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int  *puiOutputLength
);

/*
ԭ�ͣ�	int SDF_InternalPublicKeyOperation_RSA(
void *hSessionHandle,
unsigned int  uiKeyIndex,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
unsigned char *pucDataOutput,
unsigned int  *puiOutputLength);
������	ʹ���ڲ�ָ�������Ĺ�Կ�����ݽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�ڲ��洢��Կ������ֵ
	pucDataInput[in]	������ָ�룬���ڴ���ⲿ���������
	uiInputLength[in]	��������ݳ���
	pucDataOutput[out]	������ָ�룬���ڴ�����������
	puiOutputLength[out]	��������ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
*/
int SDF_InternalPublicKeyOperation_RSA
(
	void *hSessionHandle,
	unsigned int  uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int  *puiOutputLength
);

/*
ԭ�ͣ�	int SDF_InternalPrivateKeyOperation_RSA(
void *hSessionHandle,
unsigned int  uiKeyIndex,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
unsigned char *pucDataOutput,
unsigned int  *puiOutputLength);
������	ʹ���ڲ�ָ��������˽Կ�����ݽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�ڲ��洢˽Կ������ֵ
	pucDataInput[in]	������ָ�룬���ڴ���ⲿ���������
	uiInputLength[in]	��������ݳ���
	pucDataOutput[out]	������ָ�룬���ڴ�����������
	puiOutputLength[out]	��������ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
*/
int SDF_InternalPrivateKeyOperation_RSA
(
	void *hSessionHandle,
	unsigned int  uiKeyIndex,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int  *puiOutputLength
);

/*
ԭ�ͣ�	int SDF_InternalPublicKeyOperation_RSA(
void *hSessionHandle,
unsigned int  uiKeyIndex,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
unsigned char *pucDataOutput,
unsigned int  *puiOutputLength);
������	ʹ���ڲ�ָ�������Ĺ�Կ�����ݽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�ڲ��洢��Կ������ֵ
	pucDataInput[in]	������ָ�룬���ڴ���ⲿ���������
	uiInputLength[in]	��������ݳ���
	pucDataOutput[out]	������ָ�룬���ڴ�����������
	puiOutputLength[out]	��������ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
*/
int SDF_InternalPublicKeyOperation_RSA_Ex
(
	void *hSessionHandle,
	unsigned int  uiKeyIndex,
	unsigned int  uiKeyUsage,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int  *puiOutputLength
);

/*
ԭ�ͣ�	int SDF_InternalPrivateKeyOperation_RSA(
void *hSessionHandle,
unsigned int  uiKeyIndex,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
unsigned char *pucDataOutput,
unsigned int  *puiOutputLength);
������	ʹ���ڲ�ָ��������˽Կ�����ݽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiKeyIndex[in]	�����豸�ڲ��洢˽Կ������ֵ
	pucDataInput[in]	������ָ�룬���ڴ���ⲿ���������
	uiInputLength[in]	��������ݳ���
	pucDataOutput[out]	������ָ�룬���ڴ�����������
	puiOutputLength[out]	��������ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	������Χ�������ڲ�ǩ����Կ�ԣ����ݸ�ʽ��Ӧ�ò��װ
*/
int SDF_InternalPrivateKeyOperation_RSA_Ex
(
	void *hSessionHandle,
	unsigned int  uiKeyIndex,
	unsigned int uiKeyUsage,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	unsigned char *pucDataOutput,
	unsigned int  *puiOutputLength
);

/*
ԭ�ͣ�	int SDF_ExternalSign_ECC(
void *hSessionHandle,
unsigned int uiAlgID,
ECCrefPrivateKey *pucPrivateKey,
unsigned char *pucData,
unsigned int  uiDataLength,
ECCSignature *pucSignature);
������	ʹ���ⲿECC˽Կ�����ݽ���ǩ������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	�㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	pucPrivateKey[in]	�ⲿECC˽Կ�ṹ
	pucData[in]	������ָ�룬���ڴ���ⲿ���������
	uiDataLength[in]	��������ݳ���
	pucSignature[out]	������ָ�룬���ڴ�������ǩ��ֵ����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExternalSign_ECC
(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	unsigned char *pucData,
	unsigned int  uiDataLength,
	ECCSignature *pucSignature
);

/*
ԭ�ͣ�	int SDF_ExternalVerify_ECC(
void *hSessionHandle,
unsigned int uiAlgID,
ECCrefPublicKey *pucPublicKey,
unsigned char *pucDataInput,
unsigned int  uiInputLength,
ECCSignature *pucSignature);
������	ʹ���ⲿECC��Կ��ECCǩ��ֵ������֤����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	�㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	pucPublicKey[in]	�ⲿECC��Կ�ṹ
	pucData[in]	������ָ�룬���ڴ���ⲿ���������
	uiDataLength[in]	��������ݳ���
	pucSignature[in]	������ָ�룬���ڴ�������ǩ��ֵ����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
*/
int SDF_ExternalVerify_ECC
(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int  uiInputLength,
	ECCSignature *pucSignature
);


/*
ԭ�ͣ�	int SDF_InternalSign_ECC(
void *hSessionHandle,
unsigned int  uiISKIndex,
unsigned char *pucData,
unsigned int  uiDataLength,
ECCSignature *pucSignature);
������	ʹ���ڲ�ECC˽Կ�����ݽ���ǩ������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiISKIndex [in]	�����豸�ڲ��洢��ECCǩ��˽Կ������ֵ
	pucData[in]	������ָ�룬���ڴ���ⲿ���������
	uiDataLength[in]	��������ݳ���
	pucSignature [out]	������ָ�룬���ڴ�������ǩ��ֵ����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
*/
int SDF_InternalSign_ECC
(
	void *hSessionHandle,
	unsigned int  uiISKIndex,
	unsigned char *pucData,
	unsigned int  uiDataLength,
	ECCSignature *pucSignature
);

/*
ԭ�ͣ�	int SDF_InternalVerify_ECC(
void *hSessionHandle,
unsigned int  uiISKIndex,
unsigned char *pucData,
unsigned int  uiDataLength,
ECCSignature *pucSignature);
������	ʹ���ڲ�ECC��Կ��ECCǩ��ֵ������֤����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiISKIndex [in]	�����豸�ڲ��洢��ECCǩ����Կ������ֵ
	pucData[in]	������ָ�룬���ڴ���ⲿ���������
	uiDataLength[in]	��������ݳ���
	pucSignature[in]	������ָ�룬���ڴ�������ǩ��ֵ����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��ԭ�ĵ��Ӵ����㣬�ں����ⲿ��ɡ�
*/
int SDF_InternalVerify_ECC
(
	void *hSessionHandle,
	unsigned int  uiISKIndex,
	unsigned char *pucData,
	unsigned int  uiDataLength,
	ECCSignature *pucSignature
);

/*
ԭ�ͣ�	int SDF_ExternalEncrytp_ECC(
void *hSessionHandle,
unsigned int uiAlgID,
ECCrefPublicKey *pucPublicKey,
unsigned char *pucData,
unsigned int  uiDataLength,
ECCCipher *pucEncData);
������	ʹ���ⲿECC��Կ�����ݽ��м�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	�㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	pucPublicKey[in]	�ⲿECC��Կ�ṹ
	pucData[in]	������ָ�룬���ڴ���ⲿ���������
	uiDataLength[in]	��������ݳ���
	pucEncData[out]	������ָ�룬���ڴ���������������
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	��������ݳ���uiDataLength������ECCref_MAX_LEN��
*/
int SDF_ExternalEncrypt_ECC
(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int  uiDataLength,
	ECCCipher *pucEncData
);

/*
ԭ�ͣ�	int SDF_ExternalDecrypt_ECC(
void *hSessionHandle,
unsigned int uiAlgID,
ECCrefPrivateKey *pucPrivateKey,
ECCCipher *pucEncData,
unsigned char *pucData,
unsigned int  *puiDataLength);
������	ʹ���ⲿECC˽Կ���н�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	�㷨��ʶ��ָ��ʹ�õ�ECC�㷨
	pucPrivateKey[in]	�ⲿECC˽Կ�ṹ
	pucEncData[in]	������ָ�룬���ڴ���������������
	pucData[out]	������ָ�룬���ڴ���������������
	puiDataLength[out]	������������ĳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ExternalDecrypt_ECC
(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPrivateKey *pucPrivateKey,
	ECCCipher *pucEncData,
	unsigned char *pucData,
	unsigned int  *puiDataLength
);



/***************************�Գ��������㺯��**************************************/
/*
ԭ�ͣ�	int SDF_Encrypt(
void *hSessionHandle,
void *hKeyHandle,
unsigned int uiAlgID,
unsigned char *pucIV,
unsigned char *pucData,
unsigned int uiDataLength,
unsigned char *pucEncData,
unsigned int  *puiEncDataLength);
������	ʹ��ָ������Կ�����IV�����ݽ��жԳƼ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	hKeyHandle[in]	ָ������Կ���
	uiAlgID[in]	�㷨��ʶ��ָ���ԳƼ����㷨
	pucIV[in|out]	������ָ�룬���ڴ������ͷ��ص�IV����
	pucData[in]	������ָ�룬���ڴ���������������
	uiDataLength[in]	������������ĳ���
	pucEncData[out]	������ָ�룬���ڴ���������������
	puiEncDataLength[out]	������������ĳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	�˺����������ݽ�����䴦������������ݱ�����ָ���㷨���鳤�ȵ���������
*/
int SDF_Encrypt
(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int  *puiEncDataLength
);

/*
ԭ�ͣ�	int SDF_Decrypt (
void *hSessionHandle,
void *hKeyHandle,
unsigned int uiAlgID,
unsigned char *pucIV,
unsigned char *pucEncData,
unsigned int  uiEncDataLength,
unsigned char *pucData,
unsigned int *puiDataLength);
������	ʹ��ָ������Կ�����IV�����ݽ��жԳƽ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	hKeyHandle[in]	ָ������Կ���
	uiAlgID[in]	�㷨��ʶ��ָ���ԳƼ����㷨
	pucIV[in|out]	������ָ�룬���ڴ������ͷ��ص�IV����
	pucEncData[in]	������ָ�룬���ڴ���������������
	uiEncDataLength[in]	������������ĳ���
	pucData[out]	������ָ�룬���ڴ���������������
	puiDataLength[out]	������������ĳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	�˺����������ݽ�����䴦������������ݱ�����ָ���㷨���鳤�ȵ���������
*/
int SDF_Decrypt 
(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int  uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength
);

/*
ԭ�ͣ�	int SDF_CalculateMAC(
void *hSessionHandle,
void *hKeyHandle,
unsigned int uiAlgID,
unsigned char *pucIV,
unsigned char *pucData,
unsigned int uiDataLength,
unsigned char *pucMAC,
unsigned int  *puiMACLength);
������	ʹ��ָ������Կ�����IV�����ݽ���MAC����
������	hSessionHandle[in]	���豸�����ĻỰ���
	hKeyHandle[in]	ָ������Կ���
	uiAlgID[in]	�㷨��ʶ��ָ��MAC�����㷨
	pucIV[in|out]	������ָ�룬���ڴ������ͷ��ص�IV����
	pucData[in]	������ָ�룬���ڴ���������������
	uiDataLength[in]	������������ĳ���
	pucMAC[out]	������ָ�룬���ڴ�������MACֵ
	puiMACLength[out]	�����MACֵ����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	�˺����������ݽ��зְ��������������MAC������IV��������MACֵ��
*/
int SDF_CalculateMAC
(
	void *hSessionHandle,
	void *hKeyHandle,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucMAC,
	unsigned int  *puiMACLength
);

/***************************�Ӵ����㺯��************************************/

/*
ԭ�ͣ�	int SDF_HashInit(
void *hSessionHandle,
unsigned int uiAlgID
ECCrefPublicKey *pucPublicKey,
unsigned char *pucID,
unsigned int uiIDLength);
������	����ʽ�����Ӵ������һ����
������	hSessionHandle[in]	���豸�����ĻỰ���
	uiAlgID[in]	ָ���Ӵ��㷨��ʶ
	pucPublicKey[in]	ǩ���ߵ�ECC��Կ����������ECCǩ�����Ӵ�ֵʱ��Ч
	pucID[in]	ǩ���ߵ�IDֵ����������ECCǩ�����Ӵ�ֵʱ��Ч
	uiIDLength[in]	ǩ���ߵ�ID����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
��ע��	����ھ����Ӧ���У�Э��˫��û��ͳһ�����ID�����Խ�ID�趨Ϊ������
*/
int SDF_HashInit
(
	void *hSessionHandle,
	unsigned int uiAlgID,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength
);

/*
ԭ�ͣ�	int SDF_HashUpdate(
void *hSessionHandle,
unsigned char *pucData,
unsigned int  uiDataLength);
������	����ʽ�����Ӵ�����ڶ���������������Ľ����Ӵ�����
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucData[in]	������ָ�룬���ڴ���������������
	uiDataLength[in]	������������ĳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_HashUpdate
(
	void *hSessionHandle,
	unsigned char *pucData,
	unsigned int  uiDataLength
);

/*
ԭ�ͣ�	int SDF_HashFinal(
void *hSessionHandle,
unsigned char *pucHash,
unsigned int  *puiHashLength);
������	����ʽ�����Ӵ�������������Ӵ�������������Ӵ����ݲ�����м�����
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucHash[out]	������ָ�룬���ڴ��������Ӵ�����
	puiHashLength[out]	���ص��Ӵ����ݳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_HashFinal
(
	void *hSessionHandle,
	unsigned char *pucHash,
	unsigned int  *puiHashLength
);

/*******************************�û��ļ���������********************************/

/*
ԭ�ͣ�	int SDF_CreateFile(
void *hSessionHandle,
unsigned char *pucFileName��
unsigned int uiNameLen��
unsigned int uiFileSize);
������	�������豸�ڲ��������ڴ洢�û����ݵ��ļ�
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucFileName[in]	������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	uiNameLen[in]	�ļ�������
	uiFileSize[in]	�ļ���ռ�洢�ռ�ĳ���
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_CreateFile
(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiFileSize
);

/*
ԭ�ͣ�	int SDF_ReadFile(
void *hSessionHandle,
unsigned char *pucFileName��
unsigned int uiNameLen��
unsigned int uiOffset,
unsigned int *puiFileLength,
unsigned char *pucBuffer);
������	��ȡ�������豸�ڲ��洢�û����ݵ��ļ�������
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucFileName[in]	������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	uiNameLen[in]	�ļ�������
	uiOffset[in]	ָ����ȡ�ļ�ʱ��ƫ��ֵ
	puiFileLength[in|out]	���ʱָ����ȡ�ļ����ݵĳ��ȣ�����ʱ����ʵ�ʶ�ȡ�ļ����ݵĳ���
	pucBuffer[out]	������ָ�룬���ڴ�Ŷ�ȡ���ļ�����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_ReadFile
(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int *puiFileLength,
	unsigned char *pucBuffer
);

/*
ԭ�ͣ�	int SDF_WriteFile(
void *hSessionHandle,
unsigned char *pucFileName��
unsigned int uiNameLen��
unsigned int uiOffset,
unsigned int uiFileLength,
unsigned char *pucBuffer);
������	�������豸�ڲ��洢�û����ݵ��ļ���д������
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucFileName[in]	������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	uiNameLen[in]	�ļ�������
	uiOffset[in]	ָ��д���ļ�ʱ��ƫ��ֵ
	uiFileLength[in]	ָ��д���ļ����ݵĳ���
	pucBuffer[in]	������ָ�룬���ڴ�������д�ļ�����
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_WriteFile
(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen,
	unsigned int uiOffset,
	unsigned int uiFileLength,
	unsigned char *pucBuffer
);

/*
ԭ�ͣ�	int SDF_DeleteFile(
void *hSessionHandle,
unsigned char *pucFileName��
unsigned int uiNameLen);
������	ɾ��ָ���ļ����������豸�ڲ��洢�û����ݵ��ļ�
������	hSessionHandle[in]	���豸�����ĻỰ���
	pucFileName[in]	������ָ�룬���ڴ��������ļ�������󳤶�128�ֽ�
	uiNameLen[in]	�ļ�������
����ֵ��	0	�ɹ�
	��0	ʧ�ܣ����ش������
*/
int SDF_DeleteFile
(
	void *hSessionHandle,
	unsigned char *pucFileName,
	unsigned int uiNameLen
);

/*�������ض���
ԭ�ͣ�
int SDF_ImportECCKeyPair 
(
	void *hSessionHandle, 
	unsigned int uiISKIndex, 
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob 
)
������	����ECC������Կ��
������	hSessionHandle[in]		���豸�����ĻỰ���
		uiISKIndex[in]			�����豸�ڲ��洢ECC������Կ�Ե�����ֵ
		pEnvelopedKeyBlob[in]	ECC��Կ�ԵĶԱ����ṹ
����ֵ��	0	�ɹ�
		��0	ʧ�ܣ����ش������
��ע����pEnvelopedKeyBlob �н��ܳ�ECC��Կ�ԣ����뵽uiISKIndex��λ�á�
*/
int SDF_ImportECCKeyPair 
(
	void *hSessionHandle, 
	unsigned int uiISKIndex, 
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob 
);

#ifdef __cplusplus
}
#endif

#endif 
