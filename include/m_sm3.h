#ifndef M_SM3_H 
#define M_SM3_H


#ifdef __cplusplus
extern "C" {
#endif

/**
 *	ECC密钥数据结构定义
 */
#define SM2_MAX_BITS		(256)
#define SM2_MAX_LEN			((SM2_MAX_BITS+7) / 8)

typedef struct SM2PublicKey_st {
	unsigned int  bits;
	unsigned char x[SM2_MAX_LEN]; 
	unsigned char y[SM2_MAX_LEN]; 
} SM2PublicKey;

typedef struct SM2PrivateKey_st
{
	unsigned int  bits;
	unsigned char D[SM2_MAX_LEN]; 
} SM2PrivateKey;

/**
 *	ECC签名数据结构定义
 */
typedef struct SM2Signature_st
{
	unsigned char r[SM2_MAX_LEN];	
	unsigned char s[SM2_MAX_LEN];	
} SM2Signature;


int sm2_sm3_init_z(EVP_MD_CTX *md_ctx,SM2PublicKey pubKey, const unsigned char *id, int id_len);
int sm2_sm3_init(EVP_MD_CTX *md_ctx, unsigned char *md_param,const unsigned char *id, int id_len);


#ifdef __cplusplus
}
#endif

#endif

