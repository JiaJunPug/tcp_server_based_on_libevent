/* 
	���ߣ��춬��
	ʱ�䣺2014-8-12
*/
#ifndef	_MACRO_H_
#define	_MACRO_H_

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>


#include <fcntl.h>
#include <sys/file.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <pthread.h>


#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/e_os2.h>
#include <openssl/err.h>

#include <openssl/symhacks.h>
#include <openssl/ossl_typ.h>
//#include <openssl/sm2.h>
#include <openssl/rsa.h>

#include "m_sm3.h"

#include "SVS_api.h"
#include "fm_def.h"
#include "fm_cpc_pub.h"
#include "fmsgd.h"
#include "q7.h"
#include "sm4.h"
#include "sqlite3.h"
#include "ts.h"
#include "apps.h"
#include "structure.h"



#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif
///////////
//���̼��ܿ�
///////////
//ECC:1-127����,0��������֤��,RSA:0-31
//ECC:129-255ǩ��,128��������֤�飬RSA:32-63

#define MAX_ECC_KEY	256
#define MAX_RSA_KEY	64


#define MAX_ECC_SKEY	127
#define MAX_RSA_SKEY	31


#define ECC_SK	129
#define ECC_EK	1

#define  ECC_SSERVER	128
#define  ECC_ESERVER	0

#define ECC_APART	128

/////////RSA
#define  RSA_SK	33
#define  RSA_EK	1

#define  RSA_SSERVER	32
#define  RSA_ESERVER	0

#define RSA_APART	32

///////////////////////
#define MIN_ECC_KEY	0
#define MIN_RSA_KEY	0

#define PIN_CODE	"12345678"

//#define PIN_CODE	"11111111"

#define MIN_CON_RSA	MIN_RSA_KEY
#define MIN_CON_ECC	MIN_ECC_KEY


#define MAX_CON_RSA	64
#define MAX_CON_ECC	256

#define DIR_NAME	"\\root"

#define ECCCONTENT	"eccc"
#define RSACONTENT	"rsac"

#define SET_ZERO	0x00
#define SET_FF		0xFF
////////////////
#define SGD_RSA			0x00010000	
#define SGD_SM2			0x00020100	
//#define SGD_SM3			0x00000001
//#define SGD_SHA1		0x00000002
//#define SGD_SHA256		0x00000004
//typedef void*	HANDLE;
//
//typedef struct UnSymmetricAlgo_st
//{
//	unsigned int flag;		//0x00:����  0x01:����  0x02:ǩ�� 0x03:��ǩ
//	unsigned int algo;		//�㷨��ʶ��: SGD_SM2 SGD_RSA
//	unsigned int keybits;		//��Կ���� :256 1024 2048
//}UnSymmetricAlgo;				//��Կ��Ϣ
//#define IOUT	//�����������


///opt/svs/ca/crl/crl.crl
///opt/svs/ca/rootcert/sm2_root.cer
///////////////////////////////

#define SM3_HASH_LEN	32
#define TEST_HASH_DATALEN 28*1024
#define TEST_SYM_DATALEN  1536

#define SHA1_HASH_LEN	20

#define MAX_CHAR		256	/* �����ַ����ֵ */
#define MAX_INFOLEN		32768

//ǩ���㷨��ʶ(�������Ӧ�ñ�ʶ�淶6.2.4)
#define SGD_SM3_RSA     0x00010001  //����SM3�㷨��RSA�㷨��ǩ��
#define SGD_SHA1_RSA    0x00010002  //����SHA_1�㷨��RSA�㷨��ǩ��
#define SGD_SHA256_RSA  0x00010004  //����SHA_256�㷨��RSA�㷨��ǩ��
#define SGD_SM3_SM2     0x00020201  //����SM3�㷨��SM2�㷨��ǩ��

/* -START- ��ز����̶����� */

#define MINID_RSA       1   
#define MAXID_RSA       14
#define MINID_ECC       1
#define MAXID_ECC       17

#define FLAG_USECERTENTITY   1//ʹ��֤��ʵ��
#define FLAG_USECERTSN       2//ʹ��֤�����к�

/* -END- ��ز����̶����� */
//�Ͳ���ܿ�����---��������
#define SVS_SUCCESS					0x00000000

#define OPEN_DEVICE_ERR				0x00000001		//���豸ʧ�� 
#define OPEN_SESSION_ERR			0x00000002		//�򿪻Ựʧ��
#define VERIFY_PIN_ERR				0x00000003		//��֤�����豸��ȫ��ʧ��
#define KEY_ALGO_ERR				0x00000004		//�㷨��ʶ������ȷ
#define PIN_LEN_ERR					0x00000005		//�����豸��ȫ�볤�ȴ���
#define MEM_OUTRANGE_ERR			0x00000006		//������̫С
#define KEY_INDEX_ERR				0x00000007		//��Կ�������кŲ���ȷ
#define PARAMETER_LENGTH_ERROR		0x00000008		//�������ȴ���
#define KEYINDEX_OUTMEMORY			0x00000009		//��Կ�������� 
#define GEN_ENC_KEYPAIR_SM2_ERR		0x0000000A		//����SM2������Կ��ʧ��
#define GEN_SIGN_KEYPAIR_SM2_ERR	0x0000000B		//����SM2ǩ����Կ��ʧ��
#define GEN_ENC_KEYPAIR_RSA_ERR		0x0000000C		//����RSA������Կ��ʧ��
#define GEN_SIGN_KEYPAIR_RSA_ERR	0x0000000D		//����RSAǩ����Կ��ʧ��
#define EXPORT_PUBKEY_ERR			0x0000000E		//������Կʧ��
#define EXPORT_KEYPAIR_ERR			0x0000000F		//������Կ��ʧ��
#define IMPORT_KEYPAIR_ERR			0x00000010		//������Կ��ʧ��
#define PUBKEY_COMPAIR_ERR			0x00000011		//��Կƥ��ʧ��
#define UPDATE_KEYPAIR_ERR			0x00000012		//�޸���Կ��ʧ��
#define SM2_DECRYPT_ERR				0x00000013		//SM2����ʧ��
#define SM2_ENCRYPT_ERR				0x00000014		//SM2����ʧ��
#define SM2_SIGN_ERR				0x00000015		//SM2ǩ��ʧ��
#define SM2_VERIFY_ERR				0x00000016		//SM2��ǩʧ��
#define RSA_DECRYPT_ERR				0x00000017		//RSA����ʧ��
#define RSA_ENCRYPT_ERR				0x00000018		//RSA����ʧ��
#define RSA_SIGN_ERR				0x00000019		//RSAǩ��ʧ��
#define RSA_VERIFY_ERR				0x0000001A		//RSA��ǩʧ��
#define CHECK_RANDOM_ERR			0x0000001B		//��������ʧ��
#define GEN_RANDOM_ERR				0x0000001C		//���������ʧ��
#define HASH_SM3_ERR				0x0000001D		//SM3�Ӵ�����ʧ��
#define HASH_ERR					0x0000001E		//�Ӵ�����ʧ��
#define CLOSE_DEVICE_ERR			0x0000001F		//�ر��豸ʧ��
#define CLOSE_SESSION_ERR			0x00000020		//�رջỰʧ��
#define INIT_DEVICE_ERR				0x00000021		//�豸������ʼ��ʧ��
#define MODIFY_PIN_ERR				0x00000022		//�޸�PIN��
#define SYM_ENCRYPT_ERR				0x00000023		//�ԳƼ���ʧ��
#define SYM_DECRYPT_ERR				0x00000024		//�Գƽ���ʧ��
#define RESER_MODULE_ERR			0x00000025		//�豸����ʧ��
#define SYM_IMPORT_KEY_ERR			0x00000026		//�����Գ���Կʧ��
#define READ_FILE_ERR				0x00000027		//�������ļ�ʧ��
#define WRITE_FILE_ERR				0x00000028		//д�����ļ�ʧ��
#define CREATE_FILE_ERR				0x00000029		//���������ļ�ʧ��
#define CONNECT_LOG_ERR				0x0000002A		//������־������ʧ��
#define DISCONNECT_LOG_ERR			0x0000002B		//������־������ʧ��


#define USER_LOGIN_ERR				0x0000002C		//�û���¼��ȡȨ��ʧ��
#define SYM_CREAT_ERR				0x0000002D		//�Գ���Կ����������ʧ��
#define SYM_DESTORY_ERR				0x0000002E		//�Գ���Կ��������ʧ��
#define ADD_ADMIN_ERR				0x0000002F		//��ӹ���Աʧ��
#define ADD_ADMIN_EXISTS			0x00000030		//��ӹ���Ա�Ѵ���
#define GET_ADMIN_ERR				0x00000031		//�õ������û���ʧ��
#define DEV_KEY_ERR					0x00000032		//δ��⵽KEY
#define DEL_KEY_ERR					0x00000033		//ɾ���û�ʧ��
#define BACKUP_INIT_ERR				0x00000034		//���ݳ�ʼ��ʧ��
#define BACKUP_ERR					0x00000035		//����ʧ��
#define RESTORE_INIT_ERR			0x00000036		//�ָ���ʼ��ʧ��
#define RESTORE_ERR					0x00000037		//�ָ�ʧ��

#define HASH_SHA1_ERR				0x00000038		//SM1�Ӵ�����ʧ��

#define DEL_KEYPAIR_ERR				0x00000039		//ɾ����Կ��ʧ��
#define SYM_CHECK_ERR				0x00000040		//�ԳƼ����������ʧ��
#define ADD_OPERUSER_ERR			0x00000041		//��Ӳ���Աʧ��
#define ADD_OPERUSER_EXISTS			0x00000042		//��Ӳ���ԱԱ�Ѵ���

#define GET_KEYTYPE_ERR				0x00000043		//�õ�Key����ʧ��



//�ӿڱ�����
#define MID_SUCCESS					0x00000000		//�ӿڳɹ�
#define MID_FAILURE					0x0000AFFF		//�ӿ�ʧ��

#define MID_IDE_ERR					0x0000A001		//���ͱ�ʶ����
#define MID_SIGN_MAX_ERR			0x0000A002		//ǩ������Խ�磬SM2:64,RSA��128,1024
#define MID_DATA_MAX_ERR			0x0000A003		//ԭ������Խ�磬base64������ֵ��֤�飬ǩ����ʹ��,ԭ��4M��֤��2048*2
#define MID_BASECODE_ERR			0x0000A004		//BASE64����ת������
#define MID_PARSECERT_ERR			0x0000A005		//����֤�����
#define MID_GETPUBLIC_ERR			0x0000A006		//ȡ֤�鹫Կʧ��
#define MID_HASH_MAX_ERR			0x0000A007		//����Խ�磬hash������ֵ128��֤�飬ǩ����ʹ��
#define MID_KEY_MAX_ERR				0x0000A008		//����Խ�磬��Կ������ֵ2048��֤�飬ǩ����ʹ��
#define MID_PARSEOCT_ERR			0x0000A009		//OCT����ʧ��
#define MID_BASEQ7_ERR				0x0000A00A		//q7����ʧ��
#define MID_PARSEQ7_ERR				0x0000A00B		//q7����ʧ��
#define MID_DATA_ERR				0x0000A00C		//ԭ�ıȽ�ʧ��
#define MID_HASH_ERR				0x0000A00D		//ժҪ�Ƚ�ʧ��
#define MID_NODATA_ERR				0x0000A00E		//û��ԭ�ļ�¼


#define MID_TIMESTAMP_HANDLE_ERR	0x0000B001		//��ȡʱ������ʧ��


/* --END-- ���ش����� MID Error */

//35
#define TYPE_CERT		1	//֤��
#define	TYPE_KEYINDEX	2	//����������


//57
#define LOGIN_STATE		1	//�ѵ�¼״̬
#define UNLOGIN_STATE	0//δ��¼

#define	KEYFILE			"/opt/svs/dependency/lib/snkey.ini"
#define	TESTDIRPATH		256
#define	TESTLINESIZE	2048
#define MAX_PATHNAMELEN		256

#define SIGN_INI_PATH	"/opt/svs/dependency/lib/ib_sign.ini"
#define SOFT_DB_PATH	"/opt/svs/dependency/lib/ib_con.keyib"		//���㷨��Կ
#define CARD_USER_PATH	"/opt/svs/dependency/lib/ib_card0.ini"		//ʹ�ÿ�����Ա��ʶ	
#define CARD_BAKDB_PATH	"/opt/svs/dependency/lib/ib_con.keyib.b"		//���ܿ�������Կ�ļ�
#define UNCARD_PATH	"/opt/svs/dependency/lib/ib_con.s_card"		//��ʶ�ļ�


#define SIGN_LOG_PATH	"/tmp/sign.log"

#define TIMESTAMP_HANDLE	"/tmp/timestamp.handle"

#define SIGN_FLAG	1 //��װOCT
#define Q7_FLAG		2 //0.9.8?
#define P7_FLAG		3 //P7ok

#define IA_FAILED	-1
#define IA_SUCCESS	0

#define		RA_BLOCK		256
#define		RA_KBLOCK		1024

#define RA_MAX	20	//�����������

#define MAX_BASE64DATA		1024*1024*4		//4m
#define MAX_HASHDATA		128				//HASHbase
#define MAX_KEYDATA			2048			//��Կbase
#define MAX_SIGNDATA		1024			//ǩ��ֵbase
#define MAX_MESSAGESIGNDATA		4096			//ǩ��ֵbase

/* log flag */
#define PRINT_CLOSE	3
#define PRINT_ERROR	1

//backup

#define BACKUP_OK					2		//���ݳɹ�
#define BACKUP_STEP_OK				1		//�������ݳɹ�

#define RESTORE_OK					2		//�ָ��ɹ�
#define RESTORE_STEP_OK				1		//�����ָ��ɹ�

//restore

//version
#define VER	45 //64λ
//191010 45:�����ļ�·���޸����
//190923 44:�Ľ���Ϣǩ������ǩ���ڴ�����ɣ�
//190918 43:�Ľ�42�汾���⣬���Ӳ�ʹ�ÿ���ʶ��ֻ�����㷨��
//190918 42:�Ľ�sqliteδ�رգ����java����
//190910  41:sign free buf �Ľ����㷨�ڴ�й©
//180130 //rsa RSADecrypt p10
//180117 //rsa sign/verifyͨ��
//180116 //bug Get_Public_Bin
//170818 //log set

//19 add test 119 command
//18 add RSA_soft


//unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
#define SM4_KEY "IDEABANK39070001"
////////////////////////

//sof_so add by 190613

//�ͻ��˽ӿڴ�����붨��:
#define SOR_OK                  0X00000000     //�ɹ�
#define SOR_UnknownErr          0X0B000001     //�쳣����
#define SOR_NotSupportYetErr    0X0B000002     //��֧�ֵķ���
#define SOR_FileErr             0X0B000003     //�ļ���������
#define SOR_ProviderTypeErr     0X0B000004     //�����ṩ�߲������ʹ���
#define SOR_LoadProviderErr     0X0B000005     //��������ṩ�߽ӿڴ���
#define SOR_LoadDevMngApiErr    0X0B000006     //�����豸����ӿڴ���
#define SOR_AlgoTypeErr         0X0B000007     //�㷨���ʹ���
#define SOR_NameLenErr          0X0B000008     //���Ƴ��ȴ���
#define SOR_KeyUsageErr         0X0B000009     //��Կ��;����
#define SOR_ModulusLenErr       0X0B000010     //ģ�ĳ��ȴ���
#define SOR_NotInitializeErr    0X0B000011     //δ��ʼ��
#define SOR_ObjErr              0X0B000012     //�������
#define SOR_MemoryErr           0X0B000100     //�ڴ����
#define SOR_TimeoutErr          0X0B000101     //����ʱ
#define SOR_IndataLenErr        0X0B000200     //�������ݳ��ȴ���
#define SOR_IndataErr           0X0B000201     //�������ݴ���
#define SOR_GenRandErr          0X0B000300     //�������������
#define SOR_HashObjErr          0X0B000301     //HASH�����
#define SOR_HashErr             0X0B000302     //HASH�������
#define SOR_GenRsaKeyErr        0X0B000303     //����RSA��Կ��
#define SOR_RsaModulusLenErr    0X0B000304     //RSA��Կģ������
#define SOR_CspImprtPubKeyErr   0X0B000305     //CSP�����빫Կ����
#define SOR_RsaEncErr           0X0B000306     //RSA���ܴ���
#define SOR_RSGDecErr           0X0B000307     //RSA���ܴ���
#define SOR_HashNotEqualErr     0X0B000308     //HASHֵ�����
#define SOR_KeyNotFountErr      0X0B000309     //��Կδ����
#define SOR_CertNotFountErr     0X0B000310     //֤��δ����
#define SOR_NotExportErr        0X0B000311     //����δ����
#define SOR_VeryPolicyErr       0X0B000312     //����δ����
#define SOR_DecryptPadErr       0X0B000400     //����ʱ����������
#define SOR_MacLenErr           0X0B000401     //MAC���ȴ���
#define SOR_KeyInfoTypeErr      0X0B000402     //��Կ���ʹ���
#define SOR_NULLPointerErr      0X0B000403     //ĳһ������Ϊ��ָ��
#define SOR_APPNOTFOUNDErr      0X0B000404     //û���ҵ���Ӧ��
#define SOR_CERTENCODEErr       0X0B000405     //֤������ʽ����
#define SOR_CERTINVALIDErr      0X0B000406     //֤����Ч�����ǿ���ca�䷢��֤�顣
#define SOR_CERTHASEXPIREDErr   0X0B000407     //֤���ѹ��ڡ�
#define SOR_CERTREVOKEDErr      0X0B000408     //֤���Ѿ���������
#define SOR_SIGNDATAErr         0X0B000409     //ǩ��ʧ�ܡ�
#define SOR_VERIFYSIGNDATAErr   0X0B000410     //��֤ǩ��ʧ��
#define SOR_READFILEErr         0X0B000411     //���ļ��쳣�������ļ������ڻ�û�ж�ȡȨ�޵ȡ�
#define SOR_WRITEFILEErr        0X0B000412     //д�ļ��쳣�������ļ������ڻ�û��дȨ�޵�
#define SOR_SECRETSEGMENTErr    0X0B000413     //�����㷨��Կ�ָ�ʧ�ܡ�
#define SOR_SECERTRECOVERYErr   0X0B000414     //���޻ָ�ʧ�ܡ�
#define SOR_ENCRYPTDATAErr      0X0B000415     //�����ݵĶԳƼ���ʧ��
#define SOR_DECRYPTDATAErr      0X0B000416     //�Գ��㷨�����ݽ���ʧ�ܡ�
#define SOR_PKCS7ENCODEErr      0X0B000417     //PKCS#7�����ʽ����
#define SOR_XMLENCODEErr        0X0B000418     //���ǺϷ���xml��������
#define SOR_PARAMETERNOTSUPPORTErr 0X0B000419  //��֧�ֵĲ���
#define SOR_CTLNOTFOUND          0X0B000420     //û�з��������б�
#define SOR_APPNOTFOUND         0X0B000421     //���õ�Ӧ������û����



//��Ӧ�붨��:
#define GM_SUCCESS                      0x00000000    //��������
#define GM_ERROR_BASE                   0x04000000    //��������ʼֵ
#define GM_ERROR_CERT_ID                0x04000001    //����֤���ʶ
#define GM_ERROR_CERT_INFO_TYPE         0x04000002    //����֤����Ϣ����
#define GM_ERROR_SERVER_CONNECT         0x04000003    //CRL��OCSP�������޷�����
#define GM_ERROR_SIGN_METHOD            0x04000004    //ǩ���㷨���ʹ���
#define GM_ERROR_KEY_INDEX              0x04000005    //ǩ����˽Կ����ֵ����
#define GM_ERROR_KEY_VALUE              0x04000006    //ǩ����˽ԿȨ�ޱ�ʶ�����
#define GM_ERROR_CERT                   0x04000007    //֤��Ƿ���������ڲ�����
#define GM_ERROR_CERT_DECODE            0x04000008    //֤���������
#define GM_ERROR_CERT_INVALID_AF        0x04000009    //֤�����
#define GM_ERROR_CERT_INVALID_BF        0x0400000A    //֤����δ��Ч
#define GM_ERROR_CERT_REMOVED           0x0400000B    //֤���ѱ�����
#define GM_INVALID_SIGNATURE            0x0400000C    //ǩ����Ч
#define GM_INVALID_DATA_FORMAT          0x0400000D    //���ݸ�ʽ����
#define GM_SYSTEM_FALURE                0x0400000E    //ϵͳ�ڲ�����
//0x0400000F-0x040000FF     Ԥ��

#define GM_ERROR_HTTP_BASE              0x040000A1    //����ʧ��
#define GM_ERROR_HTTP_EXCEPTION         0x040000A2    //Http�����쳣
//#define GM_ERROR_HTTP_TIMEOUT         0x040000A3    //���ӳ�ʱ



#define SGD_CERT_SIGNMETHOD					0x000000FF	//added by zed
//֤��������ʶ(�������Ӧ�ñ�ʶ�淶6.3.4)
#define SGD_CERT_VERSION	                0x00000001	//֤��汾
#define SGD_CERT_SERIAL	                    0x00000002	//֤�����к�
#define SGD_CERT_ISSUER	                    0x00000005	//֤��䷢����Ϣ
#define SGD_CERT_VALID_TIME	                0x00000006	//֤����Ч��
#define SGD_CERT_SUBJECT               	    0x00000007	//֤��ӵ������Ϣ
#define SGD_CERT_DER_PUBLIC_KEY	            0x00000008  //֤�鹫Կ��Ϣ
#define SGD_CERT_DER_EXTENSIONS	            0x00000009	//֤����չ����Ϣ
#define SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO	0x00000011	//�䷢����Կ��ʶ��
#define SGD_EXT_SUBJECTKEYIDENTIFIER_INFO	0x00000012	//֤���������Կ��ʶ��
#define SGD_EXT_KEYUSAGE_INFO	            0x00000013	//��Կ��;
#define SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO	0x00000014	//˽Կ��Ч��
#define SGD_EXT_CERTIFICATEPOLICIES_INFO	0x00000015	//֤�����
#define SGD_EXT_POLICYMAPPINGS_INFO	        0x00000016	//����ӳ��
#define SGD_EXT_BASICCONSTRAINTS_INFO	    0x00000017	//��������
#define SGD_EXT_POLICYCONSTRAINTS_INFO	    0x00000018	//��������
#define SGD_EXT_EXTKEYUSAGE_INFO	        0x00000019	//��չ��Կ��;
#define SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO	0x0000001A	//CRL������
#define SGD_EXT_NETSCAPE_CERT_TYPE_INFO	    0x0000001B	//Netscape����
#define SGD_EXT_SELFDEFINED_EXTENSION_INFO	0x0000001C	//˽�е��Զ�����չ��
#define SGD_CERT_ISSUER_CN	                0x00000021	//֤��䷢��CN
#define SGD_CERT_ISSUER_O	                0x00000022	//֤��䷢��O
#define SGD_CERT_ISSUER_OU	                0x00000023	//֤��䷢��OU
#define SGD_CERT_SUBJECT_CN             	0x00000031	//֤��ӵ������ϢCN
#define SGD_CERT_SUBJECT_O	                0x00000032	//֤��ӵ������ϢO
#define SGD_CERT_SUBJECT_OU	                0x00000033	//֤��ӵ������ϢOU
#define SGD_CERT_SUBJECT_EMAIL	            0x00000034	//֤��ӵ������ϢEMAIL
#define SGD_CERT_NOTBEFORE_TIME          	0x00000035	//֤����ʼ����
#define SGD_CERT_NOTAFTER_TIME	            0x00000036	//֤��������� 
//0x00000080��0x000000FF	Ϊ����֤�������Ԥ��

#ifdef	__cplusplus
extern	"C" {
#endif

int ExportCert(IN char* Ident,OUT ExportCertResp *g_Resp);

int reply_Test(char *input, char *ouput);						// 0***** 
int reply_CryptSM1(char *input, char *ouput);					// 1***** 
int reply_CryptSM2(char *input, char *ouput);					// 2***** 
int reply_DecryptECC(char *input, char *ouput);					// 3***** 
int reply_RSADecrypt(char *input, char *ouput);					// 4***** 

int reply_BackupInit(char *input, char *ouput);					// 5***** 
int reply_Backup(char *input, char *ouput);						// 6***** 
int reply_RestoreInit(char *input, char *ouput);				// 7***** 
int reply_Restore(char *input, char *ouput);					// 8***** 


int reply_ReleaseKeyUser(char *input, char *ouput);				// 11***** 

int reply_GetKeyUsers(char *input, char *ouput);				// 12***** 

int reply_AddKeyUser(char *input, char *ouput);					// 13***** 
int reply_VerifPin(char *input, char *ouput);					// 14***** 

int reply_InitDevice(char *input, char *ouput);					// 15***** 
int reply_CheckContent(char *input, char *ouput);					// 16***** 

int reply_GetECCContent(char *input, char *ouput);			// 17*****
int reply_GetRSAContent(char *input, char *ouput);			// 18*****
int reply_GenerateKeyPair(char *input, char *ouput);			// 19*****

int reply_AddSignKeyPair(char *input, char *ouput);					// 20*****
int reply_UpdateKeyPair(char *input, char *ouput);					// 21*****
int reply_ExportKeyPairEnInfo(char *input, char *ouput);		// 22***** 
int reply_ImportKeyPairEnInfo(char *input, char *ouput);		// 23***** 


int reply_DeleteKeyPair(char *input, char *ouput);				// 24*****
int reply_ImportEnKeyPair(char *input, char *ouput);			// 25*****
int reply_ImportSignKeyPair(char *input, char *ouput);			// 26*****

int reply_SignDataInside(char *input, char *ouput);				// 28***** 
int reply_VerifySignedDataInside(char *input, char *ouput);		// 29***** 


int reply_VerifySignedDataPK(char *input, char *ouput);			// 30***** 

int reply_ExportCert(char *input, char *ouput);						// 31***** 
int reply_ParseCert(char *input, char *ouput);						// 32***** 
int reply_ValidateCert(char *input, char *ouput);					// 33***** 
int reply_SignData(char *input, char *ouput);						// 34***** 
int reply_VerifySignedData(char *input, char *ouput);				// 35***** 
int reply_SignDataInit(char *input, char *ouput);					// 36***** 
int reply_SignDataUpdate(char *input, char *ouput);					// 37***** 
int reply_SignDataFinal(char *input, char *ouput);					// 38***** 
int reply_VerifySignedDataInit(char *input, char *ouput);			// 39***** 
int reply_VerifySignedDataUpdate(char *input, char *ouput);			// 40***** 
int reply_VerifySignedDataFinal(char *input, char *ouput);			// 41***** 
int reply_SignMessage(char *input, char *ouput);					// 42***** 
int reply_VerifySignedMessage(char *input, char *ouput);			// 43***** 
int reply_SignMessageInit(char *input, char *ouput);				// 44***** 
int reply_SignMessageUpdate(char *input, char *ouput);				// 45***** 
int reply_SignMessageFinal(char *input, char *ouput);				// 46***** 
int reply_VerifySignedMessageInit(char *input, char *ouput);		// 47***** 
int reply_VerifySignedMessageUpdate(char *input, char *ouput);		// 48***** 
int reply_VerifySignedMessageFinal(char *input, char *ouput);		// 49***** 
int reply_STF_InitEnvironment(char *input, char *ouput);			// 50***** 
int reply_STF_ClearEnvironment(char *input, char *ouput);			// 51***** 
int reply_STF_CreateTSRequest(char *input, char *ouput);			// 52***** 
int reply_STF_CreateTSReponse(char *input, char *ouput);			// 53***** 
int reply_STF_VerifyTSReponse(char *input, char *ouput);			// 54***** 



int reply_GetAdminUserInfo(char *input, char *ouput);				// 56***** 
int reply_GetUserInfo(char *input, char *ouput);					// 57***** 

int reply_ReleaseKeyUserAccessRight(char *input, char *ouput);		// 58***** 
int reply_AddKeyOperUser(char *input, char *ouput);					// 59***** 



int reply_HASHSM3(char *input, char *ouput);						// 60***** 
int reply_AddServerSignKeyPair(char *input, char *ouput);			// 61
int reply_ImportServerEnKeyPair (char *input, char *ouput);			// 62

int reply_WriteAdminSN(char *input, char *ouput);						// 70***** 
int reply_DeleteAdminUser(char *input, char *ouput);					// 71
int reply_CheckAdminUser (char *input, char *ouput);					// 72
int reply_VerifySignedDataInitPK(char *input, char *ouput);			// 73***** 
int reply_SignData_SM2(char *input, char *ouput);					// 74***** 
int reply_VerifySignedData_SM2(char *input, char *ouput);				// 75***** 
int reply_SignData_RSA(char *input, char *ouput);					// 76***** 
int reply_VerifySignedData_RSA(char *input, char *ouput);				// 77***** 



int reply_CheckSM2VerifyTimes(char *input, char *ouput);			// 86***** 
int reply_CheckSM2SignTimes(char *input, char *ouput);				// 87***** 
int reply_CheckCompleteness(char *input, char *ouput);				// 88***** 
int reply_CheckECCKeyPair(char *input, char *ouput);				// 92***** 
int reply_CheckRSAKeyPair(char *input, char *ouput);				// 93***** 
int reply_CheckEngineSM3(char *input, char *ouput);					// 94***** 
int reply_CheckEngineSHA1(char *input, char *ouput);				// 95***** 
int reply_CheckEngineSM4(char *input, char *ouput);					// 96***** 
int reply_CheckEngineSM2(char *input, char *ouput);					// 97***** 
int reply_CheckEngineSM1(char *input, char *ouput);					// 98***** 
int reply_CheckRandom(char *input, char *ouput);					// 99***** 
int reply_Soft_GenerateKeyPair(char *input, char *ouput);			// 100***** 

int reply_Test_RSAExportKeyPair(char *input, char *ouput);			// 117***** 
int reply_Test_ExportKeyPair(char *input, char *ouput);				// 119***** 
int reply_Test_ExportFileName(char *input, char *ouput);			// 118***** 
int reply_Test_SetCPinSM2(char *input, char *ouput);				// 116***** //add by zdy 170303
int reply_Test_RestoreSM2(char *input, char *ouput);				// 116***** //add by zdy 170303



void err_dump_init(char *logfile_prefix);
void err_dump(int flag, char *str, ...);
void err_dump_close(void);

int getconf();

int Read_BinFile(char* filename,unsigned char* data,int* datalen);

//base64ת��
//int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen);

//base64����
//int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);
	
//int IB_DecodeBlock(unsigned char *t, const unsigned char *f, int n)

//No.0����
int Mid_test(void);

//No.1 CryptSM1
int Mid_CryptSM1(IN int type,IN unsigned char *key,IN unsigned int keylen,IN unsigned char *in,
								 IN	unsigned int inlen,
								 OUT unsigned char *out,OUT unsigned int *outlen);

//No.2 CryptSM2//����
int Mid_CryptSM2(IN int type,IN int KeyType,IN unsigned int keyindex,IN unsigned char *in,
								 IN	unsigned int inlen,
								 OUT unsigned char *out,OUT unsigned int *outlen);
//No.4
int Mid_RSADecrypt(IN int KeyType,IN unsigned int keyindex,
					IN unsigned char *encdata,IN	unsigned int encdatalen,
					OUT unsigned char *out,OUT unsigned int *outlen);
					
//No.3 DecryptECC
int Mid_DecryptECC(IN int KeyType,IN unsigned int keyindex,IN unsigned char *x,
								 IN	unsigned int xlen,
								 IN unsigned char *y,
								 IN	unsigned int ylen,
								 IN unsigned char *c,
								 IN	unsigned int clen,
								 IN unsigned char *m,
								 IN	unsigned int mlen,
								 OUT unsigned char *out,OUT unsigned int *outlen);
//No.5���ݳ�ʼ��
int Mid_BackupInit(IN	unsigned char* path,IN	int keyindex);
//No.6����
int Mid_Backup(IN	unsigned char* path,IN	int keyindex,OUT		unsigned int *result,
				OUT		unsigned int *allnums,
				OUT		unsigned int *userdealnums);
//No.7�ָ���ʼ��
int Mid_RestoreInit(IN	unsigned char* path,IN	int keyindex);
//No.8�ָ�
int Mid_Restore(IN		unsigned char* path,IN	int keyindex,
				OUT		unsigned int *result,
				OUT		unsigned int *allnums,
				OUT		unsigned int *userdealnums);



//No.11 ɾ���û�
int Mid_ReleaseKeyUser(void);


//No.12 �õ��û���
int Mid_GetKeyUsers(OUT		unsigned int *usernums,OUT		unsigned int *loginnums);		//�û���


//No.13 ����û�
int Mid_AddKeyUser(	IN		unsigned char *Pin,		//�����豸��ȫ��//����ΪkeyPIN����Ҫkey
					IN		unsigned int Pinlen		//��ȫ�볤��
);

//No.14 �û���¼
int Mid_VerifPin(	IN		unsigned char *Pin,		//�����豸��ȫ��//����ΪkeyPIN����Ҫkey
					IN		unsigned int Pinlen);		//��ȫ�볤��

//No.15��ʼ��
int Mid_InitDevice(void);


//No.17�õ�ECC��ʹ�õ��������У���,��
int Mid_GetECCContent(		OUT		unsigned char *content_enc,
							OUT		int *ecncnums,
							OUT		unsigned char *content_sign,
							OUT		int *signnums
);

int Mid_Get123(	IN		unsigned char *Pin,		//�����豸��ȫ��//����ΪkeyPIN����Ҫkey
					IN		unsigned int Pinlen);		//��ȫ�볤��



//No.18�õ�RSA��ʹ�õ���������,","
int Mid_GetRSAContent(		OUT		unsigned char *content_enc,
							OUT		int *ecncnums,
							OUT		unsigned char *content_sign,
							OUT		int *signnums
);

//No.19������Կ�Բ�����(type,0���ܣ�2ǩ����keytype:SGD_SM2,SGD_RSA)
int Mid_GenerateKeyPair(IN int type,IN int KeyType,OUT char* PublicKye,OUT char* VcKye);

//No.20����ǩ����Կ��
int Mid_AddSignKeyPair(IN int KeyType,OUT char* PublicKye,OUT int* keyindex);

//No.21������Կ��
int Mid_UpdateKeyPair(IN int KeyType,IN int keyindex,IN char* OldPublicKey,IN char* NewPublicKey,IN char* NewVK);

//No.22������Կ��	
int Mid_ExportKeyPairEnInfo (IN int KeyType,IN int keyindex,IN char *key,			//���ݶԳ���Կ
				IN		int keylen,			//���ݶԳ���Կ����
				IN		char *pin,			//PIN��
				IN		int pinlen,			//PIN�볤��
				IN		char *pk,			//��Կ������Կ
				IN		int pklen,			//��Կ����
				OUT	char *enkeypair,	//������Կ��
				OUT int *enlen			//������Կ�Գ���
				);

//No.23������Կ��	
int Mid_ImportKeyPairEnInfo (IN int KeyType,IN	 char *key,			//�Գ���Կ
				IN		int keylen,			//�Գ���Կ����
				IN		char *enkeypair,	//������Կ��
				IN		int enlen,			//������Կ�Գ���
				IN 		int keyindex,		//��Կ�������к�
				IN		char *pin,			//PIN��
				IN		int pinlen			//PIN�볤��
				);

//No.24ɾ����Կ��
int Mid_DelKeyPair (IN int KeyType,IN int Keyindex,IN char* PublicKye,IN int Publickeylen);

//No.25���������Կ��
int Mid_ImportEnKeyPair(IN int KeyType,IN int Keyindex,IN char* ENpk,IN int ENpklen,IN char* ENvk,IN int ENvklen,IN char* PublicKye,IN int Publickeylen);
int Mid_ImportSignKeyPairIB(IN int KeyType,IN int Keyindex,IN char* ENpk,IN int ENpklen,IN char* ENvk,IN int ENvklen,IN char* PublicKye,IN int Publickeylen);


//No.30������֤����ǩ�������PK
int Mid_VerifySignedDataPK(IN int SignMethod,IN int type,IN char*  pk,IN int keyindex,IN int inDataLen,IN char* inData,
					IN char* signature,IN int verifyLevel,OUT int *respValue);


//No.31����֤��
int Mid_ExportCert(IN  char* Ident, OUT ExportCertResp *g_Resp);

//No.32����֤�������
int Mid_ParseCert(IN int certtype, IN int infotype,IN char*  baseCert, OUT ParseCertResp *g_Resp);

//No.33��֤֤����Ч�������
int Mid_ValidateCert(IN char*  baseCert,IN bool ocsp, OUT ValidateCertResp *g_Resp);

//No.28��������ǩ�������
int Mid_SignDataInside(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int inDatalen,IN char* inData ,OUT SignDataResp *g_Resp);

//No.29������֤����ǩ�������
int Mid_VerifySignedDataInside(IN int SignMethod,IN int type,IN char*  baseCert,IN int keyindex,IN int inDataLen,IN char* inData,
					IN char* signature,IN int verifyLevel,OUT int *respValue);


//No.34��������ǩ�������
int Mid_SignData(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int inDatalen,IN char* inData ,OUT SignDataResp *g_Resp);

//No.35������֤����ǩ�������
int Mid_VerifySignedData(IN int SignMethod,IN int type,IN char*  baseCert,IN int keyindex,IN int inDataLen,IN char* inData,
					IN char* signature,IN int verifyLevel,OUT int *respValue);


//No.36�������ǩ����ʼ�������
int Mid_SignDataInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID, IN int inDatalen,
				IN char* inData ,OUT SignDataInitResp *g_Resp);

//No.37�������ǩ�����������
int Mid_SignDataUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,IN char* inData,OUT SignDataUpdateResp *g_Resp);

//No.38�������ǩ�����������
int Mid_SignDataFinal(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int hashValueLen,IN char* hashValue,OUT SignDataFinalResp *g_Resp);

//No.39�����֤����ǩ����ʼ�������
int Mid_VerifySignedDataInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID,
						IN int inDataLen,IN char* inData,OUT VerifySignedDataInitResp *g_Resp);

//No.40�����֤����ǩ�����������
int Mid_VerifySignedDataUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,
						IN char* inData,OUT VerifySignDataUpdateResp *g_Resp);


//No.41�����֤����ǩ�����������
int Mid_VerifySignedDataFinal(IN int SignMethod,IN int type,IN char*  baseCert,IN int keyindex,IN int hashValueLen,
						IN char* hashValue,IN char* signature,IN int verifyLevel,OUT int *respValue);



//No.42������Ϣǩ�������
int Mid_SignMessage(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int inDatalen,IN char* inData , IN unsigned char* Certinfo,
	IN int certlen,IN bool hashFlag,IN bool originalText,IN bool certificateChain,IN char* crlpath,IN bool crl,IN bool authenticationAttributes,
	OUT SignMessageResp *g_Resp);



//No.43������֤��Ϣǩ�������
int Mid_VerifySignedMessage(IN int SignMethod,IN int keyindex,IN int inDataLen,IN char* inData,IN char* signedMessage,IN bool hashFlag,
						IN bool originalText,IN bool certificateChain,IN bool crl,IN bool authenticationAttributes, 
						OUT int *respValue,OUT char* CertInfo,OUT int *Certlen);

//No.44�����Ϣǩ����ʼ�������
int Mid_SignMessageInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID,IN int inDatalen,
					IN char* inData ,OUT SignMessageInitResp *g_Resp);

//No.45�����Ϣǩ�����������
int Mid_SignMessageUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,IN char* inData,OUT SignMessageUpdateResp *g_Resp);

//No.46�����Ϣǩ�����������
int Mid_SignMessageFinal(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN unsigned char* Certinfo, 
	IN int certlen,IN int hashValueLen,IN char* hashValue,OUT SignMessageFinalResp *g_Resp);

//No.47�����֤��Ϣǩ����ʼ�������
int Mid_VerifySignedMessageInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID,IN int inDataLen,
							IN char* inData,OUT VerifySignedMessageInitResp* g_Resp);

//No.48�����֤��Ϣǩ�����������
int Mid_VerifySignedMessageUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,IN char* inData,
								OUT	SignMessageUpdateResp *g_Resp);

//No.49�����֤��Ϣǩ�����������
int Mid_VerifySignedMessageFinal(IN int SignMethod,IN int hashValueLen,
						IN char* hashValue,IN char* signedMessage,IN bool hashFlag,
						IN bool originalText,IN bool certificateChain,IN bool crl,IN bool authenticationAttributes, 
						OUT int *respValue);


//No.50��ʼ����������
int STF_InitEnvironment(void** phTSHandle);
//No.51�����������
int STF_ClearEnvironment(void* phTSHandle);
//No.52����ʱ�������
int STF_CreateTSRequest(void* phTSHandle,char* pucInData,int uiInDataLength,int uiReqType,
						char* pucTSExt,int uiTSExtLength,int uiHashAlgID,char* pucTSRequest,int* puiTSRequestLength);

//No.53����ʱ�����Ӧ
int STF_CreateTSReponse(void* hTSHandle,char* pucTSRequest,int uiTSRequestLength,int uiSignatureAlgID,char* pucTSResponse,int* puiTSResponseLength);

//No.54��֤ʱ�����Ч��
int STF_VerifyTSValidity(void* hTSHandle,char* pucTSResponse,int uiTSResponseLength,int uiHashAlgID,int uiSignatureAlgID,char* pucTSCert,int uiTSCertLength);
//No.55��ȡʱ�����Ҫ��Ϣ
int STF_GetTSinfo(void* hTSHandle,char* pucTSResponse,int uiTSResponseLength,char* pucIssuerName,int* puiIssuerNameLength,char* pucTime,int* puiTimeLength);
//No.56����ʱ�����ϸ��Ϣ
int STF_GetTSDetail(void* hTSHandle,char* pucTSResponse,int uiTSResponseLength,int uiItemnumber,char* pucItemValue,int* puiItemValueLength);


//No.60
int  Mid_HASHSM3(		IN		unsigned int keyindex,	//��Կ�������к�
						IN		unsigned char *in,		//ǩ�����ݻ�����
						IN		unsigned int inlen,		//ǩ�����ݻ���������
						OUT	unsigned char *out,		//ǩ��ֵ������
						IOUT	unsigned int *outlen		//ǩ��ֵ���������ȣ�ǩ������Ϊout���������ȣ����Ϊǩ��ֵʵ�ʳ���
						);

//No.61
int Mid_AddServerSignKeyPair(IN int KeyType,OUT char* PublicKye);

//No.62
int Mid_ImportServerEnKeyPair (IN int KeyType,IN char* ENpk,IN int ENpklen,IN char* ENvk,IN int ENvklen,IN char* PublicKye,IN int Publickeylen);


//No.88�����Լ�SM2������
int  Mid_CheckCompleteness(void);

//No.92����SM2
int  Mid_CheckECCKeyPair(void);
//No.93����RSA
int  Mid_CheckRSAKeyPair(void);

//No.94�����Լ�SM3
int  Mid_CheckEngineSM3(void);
//No.95�����Լ�SHA1
int  Mid_CheckEngineSHA1(void);

//No.96�����Լ�SM4
int  Mid_CheckEngineSM4(void);

//No.98�����Լ�SM1
int  Mid_CheckEngineSM1(void);

//No.99������
int Mid_CheckRandom(void);

//No.100�������㷨SM2��Կ��
int Mid_Soft_GenerateKeyPair(IN int type,IN int KeyType,OUT char* PublicKye,OUT char* VcKye);

//No.101 SM3
int  Mid_Soft_HASHSM3(	IN		unsigned int keyindex,	//��Կ�������к�
						IN		unsigned char *in,		//ǩ�����ݻ�����
						IN		unsigned int inlen,		//ǩ�����ݻ���������
						IN		unsigned char *pk,		//��Կ������
						IN		unsigned int *pklen,		//����ʱΪ��Կ����������
						OUT	unsigned char *out,		//ǩ��ֵ������
						IOUT	unsigned int *outlen		//ǩ��ֵ���������ȣ�ǩ������Ϊout���������ȣ����Ϊǩ��ֵʵ�ʳ���
);

#ifdef	__cplusplus
}
#endif
#endif


