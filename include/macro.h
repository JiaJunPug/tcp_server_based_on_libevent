/* 
	作者：朱冬艳
	时间：2014-8-12
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
//渔翁加密卡
///////////
//ECC:1-127加密,0，服务器证书,RSA:0-31
//ECC:129-255签名,128，服务器证书，RSA:32-63

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
//	unsigned int flag;		//0x00:加密  0x01:解密  0x02:签名 0x03:验签
//	unsigned int algo;		//算法标识符: SGD_SM2 SGD_RSA
//	unsigned int keybits;		//密钥长度 :256 1024 2048
//}UnSymmetricAlgo;				//密钥信息
//#define IOUT	//输入输出参数


///opt/svs/ca/crl/crl.crl
///opt/svs/ca/rootcert/sm2_root.cer
///////////////////////////////

#define SM3_HASH_LEN	32
#define TEST_HASH_DATALEN 28*1024
#define TEST_SYM_DATALEN  1536

#define SHA1_HASH_LEN	20

#define MAX_CHAR		256	/* 单个字符最大值 */
#define MAX_INFOLEN		32768

//签名算法标识(详见密码应用标识规范6.2.4)
#define SGD_SM3_RSA     0x00010001  //基于SM3算法和RSA算法的签名
#define SGD_SHA1_RSA    0x00010002  //基于SHA_1算法和RSA算法的签名
#define SGD_SHA256_RSA  0x00010004  //基于SHA_256算法和RSA算法的签名
#define SGD_SM3_SM2     0x00020201  //基于SM3算法和SM2算法的签名

/* -START- 相关参数固定长度 */

#define MINID_RSA       1   
#define MAXID_RSA       14
#define MINID_ECC       1
#define MAXID_ECC       17

#define FLAG_USECERTENTITY   1//使用证书实体
#define FLAG_USECERTSN       2//使用证书序列号

/* -END- 相关参数固定长度 */
//低层加密卡返回---华正天网
#define SVS_SUCCESS					0x00000000

#define OPEN_DEVICE_ERR				0x00000001		//打开设备失败 
#define OPEN_SESSION_ERR			0x00000002		//打开会话失败
#define VERIFY_PIN_ERR				0x00000003		//验证密码设备安全码失败
#define KEY_ALGO_ERR				0x00000004		//算法标识符不正确
#define PIN_LEN_ERR					0x00000005		//密码设备安全码长度错误
#define MEM_OUTRANGE_ERR			0x00000006		//缓冲区太小
#define KEY_INDEX_ERR				0x00000007		//密钥容器序列号不正确
#define PARAMETER_LENGTH_ERROR		0x00000008		//参数长度错误
#define KEYINDEX_OUTMEMORY			0x00000009		//密钥容器已满 
#define GEN_ENC_KEYPAIR_SM2_ERR		0x0000000A		//生成SM2加密密钥对失败
#define GEN_SIGN_KEYPAIR_SM2_ERR	0x0000000B		//生成SM2签名密钥对失败
#define GEN_ENC_KEYPAIR_RSA_ERR		0x0000000C		//生成RSA加密密钥对失败
#define GEN_SIGN_KEYPAIR_RSA_ERR	0x0000000D		//生成RSA签名密钥对失败
#define EXPORT_PUBKEY_ERR			0x0000000E		//导出公钥失败
#define EXPORT_KEYPAIR_ERR			0x0000000F		//导出密钥对失败
#define IMPORT_KEYPAIR_ERR			0x00000010		//导入密钥对失败
#define PUBKEY_COMPAIR_ERR			0x00000011		//公钥匹配失败
#define UPDATE_KEYPAIR_ERR			0x00000012		//修改密钥对失败
#define SM2_DECRYPT_ERR				0x00000013		//SM2解密失败
#define SM2_ENCRYPT_ERR				0x00000014		//SM2加密失败
#define SM2_SIGN_ERR				0x00000015		//SM2签名失败
#define SM2_VERIFY_ERR				0x00000016		//SM2验签失败
#define RSA_DECRYPT_ERR				0x00000017		//RSA解密失败
#define RSA_ENCRYPT_ERR				0x00000018		//RSA加密失败
#define RSA_SIGN_ERR				0x00000019		//RSA签名失败
#define RSA_VERIFY_ERR				0x0000001A		//RSA验签失败
#define CHECK_RANDOM_ERR			0x0000001B		//随机数检测失败
#define GEN_RANDOM_ERR				0x0000001C		//产生随机数失败
#define HASH_SM3_ERR				0x0000001D		//SM3杂凑运算失败
#define HASH_ERR					0x0000001E		//杂凑运算失败
#define CLOSE_DEVICE_ERR			0x0000001F		//关闭设备失败
#define CLOSE_SESSION_ERR			0x00000020		//关闭会话失败
#define INIT_DEVICE_ERR				0x00000021		//设备出场初始化失败
#define MODIFY_PIN_ERR				0x00000022		//修改PIN码
#define SYM_ENCRYPT_ERR				0x00000023		//对称加密失败
#define SYM_DECRYPT_ERR				0x00000024		//对称解密失败
#define RESER_MODULE_ERR			0x00000025		//设备重启失败
#define SYM_IMPORT_KEY_ERR			0x00000026		//导出对称密钥失败
#define READ_FILE_ERR				0x00000027		//读卡内文件失败
#define WRITE_FILE_ERR				0x00000028		//写卡内文件失败
#define CREATE_FILE_ERR				0x00000029		//创建卡内文件失败
#define CONNECT_LOG_ERR				0x0000002A		//连接日志管理器失败
#define DISCONNECT_LOG_ERR			0x0000002B		//管理日志管理器失败


#define USER_LOGIN_ERR				0x0000002C		//用户登录获取权限失败
#define SYM_CREAT_ERR				0x0000002D		//对称密钥容器号生成失败
#define SYM_DESTORY_ERR				0x0000002E		//对称密钥容器销毁失败
#define ADD_ADMIN_ERR				0x0000002F		//添加管理员失败
#define ADD_ADMIN_EXISTS			0x00000030		//添加管理员已存在
#define GET_ADMIN_ERR				0x00000031		//得到卡内用户数失败
#define DEV_KEY_ERR					0x00000032		//未检测到KEY
#define DEL_KEY_ERR					0x00000033		//删除用户失败
#define BACKUP_INIT_ERR				0x00000034		//备份初始化失败
#define BACKUP_ERR					0x00000035		//备份失败
#define RESTORE_INIT_ERR			0x00000036		//恢复初始化失败
#define RESTORE_ERR					0x00000037		//恢复失败

#define HASH_SHA1_ERR				0x00000038		//SM1杂凑运算失败

#define DEL_KEYPAIR_ERR				0x00000039		//删除密钥对失败
#define SYM_CHECK_ERR				0x00000040		//对称加密引擎测试失败
#define ADD_OPERUSER_ERR			0x00000041		//添加操作员失败
#define ADD_OPERUSER_EXISTS			0x00000042		//添加操作员员已存在

#define GET_KEYTYPE_ERR				0x00000043		//得到Key类型失败



//接口本身返回
#define MID_SUCCESS					0x00000000		//接口成功
#define MID_FAILURE					0x0000AFFF		//接口失败

#define MID_IDE_ERR					0x0000A001		//类型标识错误
#define MID_SIGN_MAX_ERR			0x0000A002		//签名数据越界，SM2:64,RSA：128,1024
#define MID_DATA_MAX_ERR			0x0000A003		//原文数据越界，base64输出最大值，证书，签名中使用,原文4M，证书2048*2
#define MID_BASECODE_ERR			0x0000A004		//BASE64编码转换错误
#define MID_PARSECERT_ERR			0x0000A005		//解析证书错误
#define MID_GETPUBLIC_ERR			0x0000A006		//取证书公钥失败
#define MID_HASH_MAX_ERR			0x0000A007		//数据越界，hash输出最大值128，证书，签名中使用
#define MID_KEY_MAX_ERR				0x0000A008		//数据越界，密钥输出最大值2048，证书，签名中使用
#define MID_PARSEOCT_ERR			0x0000A009		//OCT解码失败
#define MID_BASEQ7_ERR				0x0000A00A		//q7编码失败
#define MID_PARSEQ7_ERR				0x0000A00B		//q7编码失败
#define MID_DATA_ERR				0x0000A00C		//原文比较失败
#define MID_HASH_ERR				0x0000A00D		//摘要比较失败
#define MID_NODATA_ERR				0x0000A00E		//没有原文记录


#define MID_TIMESTAMP_HANDLE_ERR	0x0000B001		//获取时间戳句柄失败


/* --END-- 返回错误定义 MID Error */

//35
#define TYPE_CERT		1	//证书
#define	TYPE_KEYINDEX	2	//窗口索引号


//57
#define LOGIN_STATE		1	//已登录状态
#define UNLOGIN_STATE	0//未登录

#define	KEYFILE			"/opt/svs/dependency/lib/snkey.ini"
#define	TESTDIRPATH		256
#define	TESTLINESIZE	2048
#define MAX_PATHNAMELEN		256

#define SIGN_INI_PATH	"/opt/svs/dependency/lib/ib_sign.ini"
#define SOFT_DB_PATH	"/opt/svs/dependency/lib/ib_con.keyib"		//软算法密钥
#define CARD_USER_PATH	"/opt/svs/dependency/lib/ib_card0.ini"		//使用卡管理员标识	
#define CARD_BAKDB_PATH	"/opt/svs/dependency/lib/ib_con.keyib.b"		//加密卡备份密钥文件
#define UNCARD_PATH	"/opt/svs/dependency/lib/ib_con.s_card"		//标识文件


#define SIGN_LOG_PATH	"/tmp/sign.log"

#define TIMESTAMP_HANDLE	"/tmp/timestamp.handle"

#define SIGN_FLAG	1 //封装OCT
#define Q7_FLAG		2 //0.9.8?
#define P7_FLAG		3 //P7ok

#define IA_FAILED	-1
#define IA_SUCCESS	0

#define		RA_BLOCK		256
#define		RA_KBLOCK		1024

#define RA_MAX	20	//批量最大数量

#define MAX_BASE64DATA		1024*1024*4		//4m
#define MAX_HASHDATA		128				//HASHbase
#define MAX_KEYDATA			2048			//公钥base
#define MAX_SIGNDATA		1024			//签名值base
#define MAX_MESSAGESIGNDATA		4096			//签名值base

/* log flag */
#define PRINT_CLOSE	3
#define PRINT_ERROR	1

//backup

#define BACKUP_OK					2		//备份成功
#define BACKUP_STEP_OK				1		//单步备份成功

#define RESTORE_OK					2		//恢复成功
#define RESTORE_STEP_OK				1		//单步恢复成功

//restore

//version
#define VER	45 //64位
//191010 45:配置文件路径修改完成
//190923 44:改进消息签名，验签（内存检查完成）
//190918 43:改进42版本问题，增加不使用卡标识（只用软算法）
//190918 42:改进sqlite未关闭，造成java崩溃
//190910  41:sign free buf 改进软算法内存泄漏
//180130 //rsa RSADecrypt p10
//180117 //rsa sign/verify通过
//180116 //bug Get_Public_Bin
//170818 //log set

//19 add test 119 command
//18 add RSA_soft


//unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
#define SM4_KEY "IDEABANK39070001"
////////////////////////

//sof_so add by 190613

//客户端接口错误代码定义:
#define SOR_OK                  0X00000000     //成功
#define SOR_UnknownErr          0X0B000001     //异常错误
#define SOR_NotSupportYetErr    0X0B000002     //不支持的服务
#define SOR_FileErr             0X0B000003     //文件操作错误
#define SOR_ProviderTypeErr     0X0B000004     //服务提供者参数类型错误
#define SOR_LoadProviderErr     0X0B000005     //导入服务提供者接口错误
#define SOR_LoadDevMngApiErr    0X0B000006     //导入设备管理接口错误
#define SOR_AlgoTypeErr         0X0B000007     //算法类型错误
#define SOR_NameLenErr          0X0B000008     //名称长度错误
#define SOR_KeyUsageErr         0X0B000009     //密钥用途错误
#define SOR_ModulusLenErr       0X0B000010     //模的长度错误
#define SOR_NotInitializeErr    0X0B000011     //未初始化
#define SOR_ObjErr              0X0B000012     //对象错误
#define SOR_MemoryErr           0X0B000100     //内存错误
#define SOR_TimeoutErr          0X0B000101     //服务超时
#define SOR_IndataLenErr        0X0B000200     //输入数据长度错误
#define SOR_IndataErr           0X0B000201     //输入数据错误
#define SOR_GenRandErr          0X0B000300     //生成随机数错误
#define SOR_HashObjErr          0X0B000301     //HASH对象错
#define SOR_HashErr             0X0B000302     //HASH运算错误
#define SOR_GenRsaKeyErr        0X0B000303     //产生RSA密钥错
#define SOR_RsaModulusLenErr    0X0B000304     //RSA密钥模长错误
#define SOR_CspImprtPubKeyErr   0X0B000305     //CSP服务导入公钥错误
#define SOR_RsaEncErr           0X0B000306     //RSA加密错误
#define SOR_RSGDecErr           0X0B000307     //RSA解密错误
#define SOR_HashNotEqualErr     0X0B000308     //HASH值不相等
#define SOR_KeyNotFountErr      0X0B000309     //密钥未发现
#define SOR_CertNotFountErr     0X0B000310     //证书未发现
#define SOR_NotExportErr        0X0B000311     //对象未导出
#define SOR_VeryPolicyErr       0X0B000312     //对象未导出
#define SOR_DecryptPadErr       0X0B000400     //解密时做补丁错误
#define SOR_MacLenErr           0X0B000401     //MAC长度错误
#define SOR_KeyInfoTypeErr      0X0B000402     //密钥类型错误
#define SOR_NULLPointerErr      0X0B000403     //某一个参数为空指针
#define SOR_APPNOTFOUNDErr      0X0B000404     //没有找到该应用
#define SOR_CERTENCODEErr       0X0B000405     //证书编码格式错误。
#define SOR_CERTINVALIDErr      0X0B000406     //证书无效，不是可信ca颁发的证书。
#define SOR_CERTHASEXPIREDErr   0X0B000407     //证书已过期。
#define SOR_CERTREVOKEDErr      0X0B000408     //证书已经被吊销。
#define SOR_SIGNDATAErr         0X0B000409     //签名失败。
#define SOR_VERIFYSIGNDATAErr   0X0B000410     //验证签名失败
#define SOR_READFILEErr         0X0B000411     //读文件异常，可能文件不存在或没有读取权限等。
#define SOR_WRITEFILEErr        0X0B000412     //写文件异常，可能文件不存在或没有写权限等
#define SOR_SECRETSEGMENTErr    0X0B000413     //门限算法密钥分割失败。
#define SOR_SECERTRECOVERYErr   0X0B000414     //门限恢复失败。
#define SOR_ENCRYPTDATAErr      0X0B000415     //对数据的对称加密失败
#define SOR_DECRYPTDATAErr      0X0B000416     //对称算法的数据解密失败。
#define SOR_PKCS7ENCODEErr      0X0B000417     //PKCS#7编码格式错误
#define SOR_XMLENCODEErr        0X0B000418     //不是合法的xml编码数据
#define SOR_PARAMETERNOTSUPPORTErr 0X0B000419  //不支持的参数
#define SOR_CTLNOTFOUND          0X0B000420     //没有发现信任列表
#define SOR_APPNOTFOUND         0X0B000421     //设置的应用名称没发现



//响应码定义:
#define GM_SUCCESS                      0x00000000    //正常返回
#define GM_ERROR_BASE                   0x04000000    //错误码起始值
#define GM_ERROR_CERT_ID                0x04000001    //错误证书标识
#define GM_ERROR_CERT_INFO_TYPE         0x04000002    //错误证书信息类型
#define GM_ERROR_SERVER_CONNECT         0x04000003    //CRL或OCSP服务器无法连接
#define GM_ERROR_SIGN_METHOD            0x04000004    //签名算法类型错误
#define GM_ERROR_KEY_INDEX              0x04000005    //签名者私钥索引值错误
#define GM_ERROR_KEY_VALUE              0x04000006    //签名者私钥权限标识码错误
#define GM_ERROR_CERT                   0x04000007    //证书非法或服务器内不存在
#define GM_ERROR_CERT_DECODE            0x04000008    //证书解析错误
#define GM_ERROR_CERT_INVALID_AF        0x04000009    //证书过期
#define GM_ERROR_CERT_INVALID_BF        0x0400000A    //证书尚未生效
#define GM_ERROR_CERT_REMOVED           0x0400000B    //证书已被吊销
#define GM_INVALID_SIGNATURE            0x0400000C    //签名无效
#define GM_INVALID_DATA_FORMAT          0x0400000D    //数据格式错误
#define GM_SYSTEM_FALURE                0x0400000E    //系统内部错误
//0x0400000F-0x040000FF     预留

#define GM_ERROR_HTTP_BASE              0x040000A1    //调用失败
#define GM_ERROR_HTTP_EXCEPTION         0x040000A2    //Http连接异常
//#define GM_ERROR_HTTP_TIMEOUT         0x040000A3    //连接超时



#define SGD_CERT_SIGNMETHOD					0x000000FF	//added by zed
//证书解析项标识(详见密码应用标识规范6.3.4)
#define SGD_CERT_VERSION	                0x00000001	//证书版本
#define SGD_CERT_SERIAL	                    0x00000002	//证书序列号
#define SGD_CERT_ISSUER	                    0x00000005	//证书颁发者信息
#define SGD_CERT_VALID_TIME	                0x00000006	//证书有效期
#define SGD_CERT_SUBJECT               	    0x00000007	//证书拥有者信息
#define SGD_CERT_DER_PUBLIC_KEY	            0x00000008  //证书公钥信息
#define SGD_CERT_DER_EXTENSIONS	            0x00000009	//证书扩展项信息
#define SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO	0x00000011	//颁发者密钥标识符
#define SGD_EXT_SUBJECTKEYIDENTIFIER_INFO	0x00000012	//证书持有者密钥标识符
#define SGD_EXT_KEYUSAGE_INFO	            0x00000013	//密钥用途
#define SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO	0x00000014	//私钥有效期
#define SGD_EXT_CERTIFICATEPOLICIES_INFO	0x00000015	//证书策略
#define SGD_EXT_POLICYMAPPINGS_INFO	        0x00000016	//策略映射
#define SGD_EXT_BASICCONSTRAINTS_INFO	    0x00000017	//基本限制
#define SGD_EXT_POLICYCONSTRAINTS_INFO	    0x00000018	//策略限制
#define SGD_EXT_EXTKEYUSAGE_INFO	        0x00000019	//扩展密钥用途
#define SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO	0x0000001A	//CRL发布点
#define SGD_EXT_NETSCAPE_CERT_TYPE_INFO	    0x0000001B	//Netscape属性
#define SGD_EXT_SELFDEFINED_EXTENSION_INFO	0x0000001C	//私有的自定义扩展项
#define SGD_CERT_ISSUER_CN	                0x00000021	//证书颁发者CN
#define SGD_CERT_ISSUER_O	                0x00000022	//证书颁发者O
#define SGD_CERT_ISSUER_OU	                0x00000023	//证书颁发者OU
#define SGD_CERT_SUBJECT_CN             	0x00000031	//证书拥有者信息CN
#define SGD_CERT_SUBJECT_O	                0x00000032	//证书拥有者信息O
#define SGD_CERT_SUBJECT_OU	                0x00000033	//证书拥有者信息OU
#define SGD_CERT_SUBJECT_EMAIL	            0x00000034	//证书拥有者信息EMAIL
#define SGD_CERT_NOTBEFORE_TIME          	0x00000035	//证书起始日期
#define SGD_CERT_NOTAFTER_TIME	            0x00000036	//证书截至日期 
//0x00000080～0x000000FF	为其他证书解析项预留

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

//base64转换
//int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen);

//base64解码
//int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);
	
//int IB_DecodeBlock(unsigned char *t, const unsigned char *f, int n)

//No.0测试
int Mid_test(void);

//No.1 CryptSM1
int Mid_CryptSM1(IN int type,IN unsigned char *key,IN unsigned int keylen,IN unsigned char *in,
								 IN	unsigned int inlen,
								 OUT unsigned char *out,OUT unsigned int *outlen);

//No.2 CryptSM2//加密
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
//No.5备份初始化
int Mid_BackupInit(IN	unsigned char* path,IN	int keyindex);
//No.6备份
int Mid_Backup(IN	unsigned char* path,IN	int keyindex,OUT		unsigned int *result,
				OUT		unsigned int *allnums,
				OUT		unsigned int *userdealnums);
//No.7恢复初始化
int Mid_RestoreInit(IN	unsigned char* path,IN	int keyindex);
//No.8恢复
int Mid_Restore(IN		unsigned char* path,IN	int keyindex,
				OUT		unsigned int *result,
				OUT		unsigned int *allnums,
				OUT		unsigned int *userdealnums);



//No.11 删除用户
int Mid_ReleaseKeyUser(void);


//No.12 得到用户数
int Mid_GetKeyUsers(OUT		unsigned int *usernums,OUT		unsigned int *loginnums);		//用户数


//No.13 添加用户
int Mid_AddKeyUser(	IN		unsigned char *Pin,		//密码设备安全码//渔翁为keyPIN，需要key
					IN		unsigned int Pinlen		//安全码长度
);

//No.14 用户登录
int Mid_VerifPin(	IN		unsigned char *Pin,		//密码设备安全码//渔翁为keyPIN，需要key
					IN		unsigned int Pinlen);		//安全码长度

//No.15初始化
int Mid_InitDevice(void);


//No.17得到ECC已使用的容器序列，“,”
int Mid_GetECCContent(		OUT		unsigned char *content_enc,
							OUT		int *ecncnums,
							OUT		unsigned char *content_sign,
							OUT		int *signnums
);

int Mid_Get123(	IN		unsigned char *Pin,		//密码设备安全码//渔翁为keyPIN，需要key
					IN		unsigned int Pinlen);		//安全码长度



//No.18得到RSA已使用的容器序列,","
int Mid_GetRSAContent(		OUT		unsigned char *content_enc,
							OUT		int *ecncnums,
							OUT		unsigned char *content_sign,
							OUT		int *signnums
);

//No.19生成密钥对并导出(type,0加密，2签名，keytype:SGD_SM2,SGD_RSA)
int Mid_GenerateKeyPair(IN int type,IN int KeyType,OUT char* PublicKye,OUT char* VcKye);

//No.20生成签名密钥对
int Mid_AddSignKeyPair(IN int KeyType,OUT char* PublicKye,OUT int* keyindex);

//No.21更新密钥对
int Mid_UpdateKeyPair(IN int KeyType,IN int keyindex,IN char* OldPublicKey,IN char* NewPublicKey,IN char* NewVK);

//No.22导出密钥对	
int Mid_ExportKeyPairEnInfo (IN int KeyType,IN int keyindex,IN char *key,			//备份对称密钥
				IN		int keylen,			//备份对称密钥长度
				IN		char *pin,			//PIN码
				IN		int pinlen,			//PIN码长度
				IN		char *pk,			//密钥容器公钥
				IN		int pklen,			//公钥长度
				OUT	char *enkeypair,	//密文密钥对
				OUT int *enlen			//密文密钥对长度
				);

//No.23导入密钥对	
int Mid_ImportKeyPairEnInfo (IN int KeyType,IN	 char *key,			//对称密钥
				IN		int keylen,			//对称密钥长度
				IN		char *enkeypair,	//密文密钥对
				IN		int enlen,			//密文密钥对长度
				IN 		int keyindex,		//密钥容器序列号
				IN		char *pin,			//PIN码
				IN		int pinlen			//PIN码长度
				);

//No.24删除密钥对
int Mid_DelKeyPair (IN int KeyType,IN int Keyindex,IN char* PublicKye,IN int Publickeylen);

//No.25导入加密密钥对
int Mid_ImportEnKeyPair(IN int KeyType,IN int Keyindex,IN char* ENpk,IN int ENpklen,IN char* ENvk,IN int ENvklen,IN char* PublicKye,IN int Publickeylen);
int Mid_ImportSignKeyPairIB(IN int KeyType,IN int Keyindex,IN char* ENpk,IN int ENpklen,IN char* ENvk,IN int ENvklen,IN char* PublicKye,IN int Publickeylen);


//No.30单包验证数字签名申请包PK
int Mid_VerifySignedDataPK(IN int SignMethod,IN int type,IN char*  pk,IN int keyindex,IN int inDataLen,IN char* inData,
					IN char* signature,IN int verifyLevel,OUT int *respValue);


//No.31导出证书
int Mid_ExportCert(IN  char* Ident, OUT ExportCertResp *g_Resp);

//No.32解析证书申请包
int Mid_ParseCert(IN int certtype, IN int infotype,IN char*  baseCert, OUT ParseCertResp *g_Resp);

//No.33验证证书有效性申请包
int Mid_ValidateCert(IN char*  baseCert,IN bool ocsp, OUT ValidateCertResp *g_Resp);

//No.28单包数字签名申请包
int Mid_SignDataInside(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int inDatalen,IN char* inData ,OUT SignDataResp *g_Resp);

//No.29单包验证数字签名申请包
int Mid_VerifySignedDataInside(IN int SignMethod,IN int type,IN char*  baseCert,IN int keyindex,IN int inDataLen,IN char* inData,
					IN char* signature,IN int verifyLevel,OUT int *respValue);


//No.34单包数字签名申请包
int Mid_SignData(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int inDatalen,IN char* inData ,OUT SignDataResp *g_Resp);

//No.35单包验证数字签名申请包
int Mid_VerifySignedData(IN int SignMethod,IN int type,IN char*  baseCert,IN int keyindex,IN int inDataLen,IN char* inData,
					IN char* signature,IN int verifyLevel,OUT int *respValue);


//No.36多包数字签名初始化申请包
int Mid_SignDataInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID, IN int inDatalen,
				IN char* inData ,OUT SignDataInitResp *g_Resp);

//No.37多包数字签名更新申请包
int Mid_SignDataUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,IN char* inData,OUT SignDataUpdateResp *g_Resp);

//No.38多包数字签名结束申请包
int Mid_SignDataFinal(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int hashValueLen,IN char* hashValue,OUT SignDataFinalResp *g_Resp);

//No.39多包验证数字签名初始化申请包
int Mid_VerifySignedDataInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID,
						IN int inDataLen,IN char* inData,OUT VerifySignedDataInitResp *g_Resp);

//No.40多包验证数字签名更新申请包
int Mid_VerifySignedDataUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,
						IN char* inData,OUT VerifySignDataUpdateResp *g_Resp);


//No.41多包验证数字签名结束申请包
int Mid_VerifySignedDataFinal(IN int SignMethod,IN int type,IN char*  baseCert,IN int keyindex,IN int hashValueLen,
						IN char* hashValue,IN char* signature,IN int verifyLevel,OUT int *respValue);



//No.42单包消息签名申请包
int Mid_SignMessage(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN int inDatalen,IN char* inData , IN unsigned char* Certinfo,
	IN int certlen,IN bool hashFlag,IN bool originalText,IN bool certificateChain,IN char* crlpath,IN bool crl,IN bool authenticationAttributes,
	OUT SignMessageResp *g_Resp);



//No.43单包验证消息签名申请包
int Mid_VerifySignedMessage(IN int SignMethod,IN int keyindex,IN int inDataLen,IN char* inData,IN char* signedMessage,IN bool hashFlag,
						IN bool originalText,IN bool certificateChain,IN bool crl,IN bool authenticationAttributes, 
						OUT int *respValue,OUT char* CertInfo,OUT int *Certlen);

//No.44多包消息签名初始化申请包
int Mid_SignMessageInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID,IN int inDatalen,
					IN char* inData ,OUT SignMessageInitResp *g_Resp);

//No.45多包消息签名更新申请包
int Mid_SignMessageUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,IN char* inData,OUT SignMessageUpdateResp *g_Resp);

//No.46多包消息签名结束申请包
int Mid_SignMessageFinal(IN int SignMethod,IN int keyindex,IN char* keyvalue,IN unsigned char* Certinfo, 
	IN int certlen,IN int hashValueLen,IN char* hashValue,OUT SignMessageFinalResp *g_Resp);

//No.47多包验证消息签名初始化申请包
int Mid_VerifySignedMessageInit(IN int SignMethod,IN int keyindex,IN int signerIDLen,IN char* signerID,IN int inDataLen,
							IN char* inData,OUT VerifySignedMessageInitResp* g_Resp);

//No.48多包验证消息签名更新申请包
int Mid_VerifySignedMessageUpdate(IN int SignMethod,IN int hashValueLen,IN char* hashValue,IN int inDataLen,IN char* inData,
								OUT	SignMessageUpdateResp *g_Resp);

//No.49多包验证消息签名结束申请包
int Mid_VerifySignedMessageFinal(IN int SignMethod,IN int hashValueLen,
						IN char* hashValue,IN char* signedMessage,IN bool hashFlag,
						IN bool originalText,IN bool certificateChain,IN bool crl,IN bool authenticationAttributes, 
						OUT int *respValue);


//No.50初始化环境函数
int STF_InitEnvironment(void** phTSHandle);
//No.51清除环境函数
int STF_ClearEnvironment(void* phTSHandle);
//No.52生成时间戳请求
int STF_CreateTSRequest(void* phTSHandle,char* pucInData,int uiInDataLength,int uiReqType,
						char* pucTSExt,int uiTSExtLength,int uiHashAlgID,char* pucTSRequest,int* puiTSRequestLength);

//No.53生成时间戳响应
int STF_CreateTSReponse(void* hTSHandle,char* pucTSRequest,int uiTSRequestLength,int uiSignatureAlgID,char* pucTSResponse,int* puiTSResponseLength);

//No.54验证时间戳有效性
int STF_VerifyTSValidity(void* hTSHandle,char* pucTSResponse,int uiTSResponseLength,int uiHashAlgID,int uiSignatureAlgID,char* pucTSCert,int uiTSCertLength);
//No.55获取时间戳主要信息
int STF_GetTSinfo(void* hTSHandle,char* pucTSResponse,int uiTSResponseLength,char* pucIssuerName,int* puiIssuerNameLength,char* pucTime,int* puiTimeLength);
//No.56解析时间戳详细信息
int STF_GetTSDetail(void* hTSHandle,char* pucTSResponse,int uiTSResponseLength,int uiItemnumber,char* pucItemValue,int* puiItemValueLength);


//No.60
int  Mid_HASHSM3(		IN		unsigned int keyindex,	//密钥容器序列号
						IN		unsigned char *in,		//签名数据缓冲区
						IN		unsigned int inlen,		//签名数据缓冲区长度
						OUT	unsigned char *out,		//签名值缓冲区
						IOUT	unsigned int *outlen		//签名值缓冲区长度，签名输入为out缓冲区长度，输出为签名值实际长度
						);

//No.61
int Mid_AddServerSignKeyPair(IN int KeyType,OUT char* PublicKye);

//No.62
int Mid_ImportServerEnKeyPair (IN int KeyType,IN char* ENpk,IN int ENpklen,IN char* ENvk,IN int ENvklen,IN char* PublicKye,IN int Publickeylen);


//No.88引擎自检SM2完整性
int  Mid_CheckCompleteness(void);

//No.92生成SM2
int  Mid_CheckECCKeyPair(void);
//No.93生成RSA
int  Mid_CheckRSAKeyPair(void);

//No.94引擎自检SM3
int  Mid_CheckEngineSM3(void);
//No.95引擎自检SHA1
int  Mid_CheckEngineSHA1(void);

//No.96引擎自检SM4
int  Mid_CheckEngineSM4(void);

//No.98引擎自检SM1
int  Mid_CheckEngineSM1(void);

//No.99检查随机
int Mid_CheckRandom(void);

//No.100生成软算法SM2密钥对
int Mid_Soft_GenerateKeyPair(IN int type,IN int KeyType,OUT char* PublicKye,OUT char* VcKye);

//No.101 SM3
int  Mid_Soft_HASHSM3(	IN		unsigned int keyindex,	//密钥容器序列号
						IN		unsigned char *in,		//签名数据缓冲区
						IN		unsigned int inlen,		//签名数据缓冲区长度
						IN		unsigned char *pk,		//公钥缓冲区
						IN		unsigned int *pklen,		//输入时为公钥缓冲区长度
						OUT	unsigned char *out,		//签名值缓冲区
						IOUT	unsigned int *outlen		//签名值缓冲区长度，签名输入为out缓冲区长度，输出为签名值实际长度
);

#ifdef	__cplusplus
}
#endif
#endif


