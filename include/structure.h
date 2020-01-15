#ifndef _STRUCTURE_H_
#define _STRUCTURE_H_

#include 	"fm_def.h"
#include	"macro.h"		



//sqliteRSA��Կ��
typedef struct RSA_KeyPair_st
{
	char rsa_pub[sizeof(FM_RSA_PublicKey)];
	char rsa_pri[sizeof(FM_RSA_PrivateKey)];
	int rsa_flag;
}RSA_KeyPair;

//sqlite-sm2��Կ��
typedef struct SM2_KeyPair_st
{
	char sm2_pub[sizeof(SM2PublicKey)];
	char sm2_pri[sizeof(SM2PrivateKey)];
	int sm2_flag;
}SM2_KeyPair;


//No.31����֤��
typedef struct ExportCertResp_st
{
	int  respValue; 
	char cert_base64[2048*2];
}ExportCertResp;

//No.32����֤�������
typedef struct ParseCertResp_st
{
	int  respValue; 
	char info[1024*2];
}ParseCertResp;

//No.33��֤֤����Ч�������
typedef struct ValidateCertResp_st
{
	int  respValue; 
	int  state;
}ValidateCertResp;

//No.34��������ǩ�������
typedef struct SignDataResp_st
{
	int  respValue; 
	char signature[1024*2];
} SignDataResp;

//No.36�������ǩ����ʼ�������
typedef struct SignDataInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
} SignDataInitResp;


//No.37�������ǩ�����������
typedef struct SignDataUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
} SignDataUpdateResp ;

//No.38�������ǩ�����������
typedef struct SignDataFinalResp_st
{
	int  respValue; 
	char signaute[1024*2];
} SignDataFinalResp;

//No.39�����֤����ǩ����ʼ�������
typedef struct VerifySignedDataInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignedDataInitResp;

//No.40�����֤����ǩ�����������
typedef struct VerifySignDataUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignDataUpdateResp;


//No.42������Ϣǩ�������
/*typedef struct SignMessageResp_st
{
	int  respValue; 
	char *signedMessage;
	int signedlen;
}SignMessageResp;*/

//No.42������Ϣǩ�������
typedef struct SignMessageResp_st
{
	int  respValue; 
	char signedMessage[1024*1024*4];
}SignMessageResp;


//No.44�����Ϣǩ����ʼ�������
typedef struct SignMessageInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}SignMessageInitResp;


//No.45�����Ϣǩ�����������
typedef struct SignMessageUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}SignMessageUpdateResp;


//No.46�����Ϣǩ�����������
typedef struct SignMessageFinalResp_st
{
	int  respValue; 
	char signedMessage[1024*1024*4];
}SignMessageFinalResp;

//No.47�����֤��Ϣǩ����ʼ�������
typedef struct VerifySignedMessageInitResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignedMessageInitResp;


//No.48�����֤��Ϣǩ�����������
typedef struct VerifySignMessageUpdateResp_st
{
	int  respValue; 
	char hashValue[1024*2];
}VerifySignMessageUpdateResp;



//No.70 user
typedef struct UserInfos_st{
	int  usernums;		/* ���η�����Ŀ���� */
	struct user_info{
		int type;		/*����*/
		char sn[32];	/*sn��*/
	}userinfo[5];
}UserInfos;


#endif

