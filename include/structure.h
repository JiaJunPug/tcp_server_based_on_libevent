#ifndef _STRUCTURE_H_
#define _STRUCTURE_H_

#include 	"fm_def.h"
#include	"macro.h"		



//sqliteRSA密钥对
typedef struct RSA_KeyPair_st
{
	char rsa_pub[sizeof(FM_RSA_PublicKey)];
	char rsa_pri[sizeof(FM_RSA_PrivateKey)];
	int rsa_flag;
}RSA_KeyPair;

//sqlite-sm2密钥对
typedef struct SM2_KeyPair_st
{
	char sm2_pub[sizeof(SM2PublicKey)];
	char sm2_pri[sizeof(SM2PrivateKey)];
	int sm2_flag;
}SM2_KeyPair;


//No.31导出证书
typedef struct ExportCertResp_st
{
	int  respValue; 
	char cert_base64[2048*2];
}ExportCertResp;

//No.32解析证书申请包
typedef struct ParseCertResp_st
{
	int  respValue; 
	char info[1024*2];
}ParseCertResp;

//No.33验证证书有效性申请包
typedef struct ValidateCertResp_st
{
	int  respValue; 
	int  state;
}ValidateCertResp;

//No.34单包数字签名申请包
typedef struct SignDataResp_st
{
	int  respValue; 
	char signature[1024*2];
} SignDataResp;

//No.36多包数字签名初始化申请包
typedef struct SignDataInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
} SignDataInitResp;


//No.37多包数字签名更新申请包
typedef struct SignDataUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
} SignDataUpdateResp ;

//No.38多包数字签名结束申请包
typedef struct SignDataFinalResp_st
{
	int  respValue; 
	char signaute[1024*2];
} SignDataFinalResp;

//No.39多包验证数字签名初始化申请包
typedef struct VerifySignedDataInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignedDataInitResp;

//No.40多包验证数字签名更新申请包
typedef struct VerifySignDataUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignDataUpdateResp;


//No.42单包消息签名申请包
/*typedef struct SignMessageResp_st
{
	int  respValue; 
	char *signedMessage;
	int signedlen;
}SignMessageResp;*/

//No.42单包消息签名申请包
typedef struct SignMessageResp_st
{
	int  respValue; 
	char signedMessage[1024*1024*4];
}SignMessageResp;


//No.44多包消息签名初始化申请包
typedef struct SignMessageInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}SignMessageInitResp;


//No.45多包消息签名更新申请包
typedef struct SignMessageUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}SignMessageUpdateResp;


//No.46多包消息签名结束申请包
typedef struct SignMessageFinalResp_st
{
	int  respValue; 
	char signedMessage[1024*1024*4];
}SignMessageFinalResp;

//No.47多包验证消息签名初始化申请包
typedef struct VerifySignedMessageInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignedMessageInitResp;


//No.48多包验证消息签名更新申请包
typedef struct VerifySignMessageUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignMessageUpdateResp;



//No.70 user
typedef struct UserInfos_st{
	int  usernums;		/* 本次发送条目数量 */
	struct user_info{
		int type;		/*类型*/
		char sn[32];	/*sn号*/
	}userinfo[5];
}UserInfos;


#endif

