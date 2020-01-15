/* crypto/Q7/Q7.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_Q7_H
#define HEADER_Q7_H

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/e_os2.h>

#include <openssl/symhacks.h>
#include <openssl/ossl_typ.h>


#ifdef  __cplusplus
extern "C" {
#endif




#ifdef OPENSSL_SYS_WIN32
/* Under Win32 thes are defined in wincrypt.h */
#undef Q7_ISSUER_AND_SERIAL
#undef Q7_SIGNER_INFO
#endif

/*
Encryption_ID		DES-CBC
Digest_ID		MD5
Digest_Encryption_ID	rsaEncryption
Key_Encryption_ID	rsaEncryption
*/

#define sk_Q7_SIGNER_INFO_push(st, val) SKM_sk_push(Q7_SIGNER_INFO, (st), (val))
#define sk_Q7_CONTENT_push(st, val) SKM_sk_push(Q7_CONTENT, (st), (val))
#define sk_Q7_SIGNER_INFO_value(st, i) SKM_sk_value(Q7_SIGNER_INFO, (st), (i))
#define sk_X509_ALGOR_pop(st) SKM_sk_pop(X509_ALGOR, (st))
#define sk_Q7_SIGNER_INFO_pop(st) SKM_sk_pop(Q7_SIGNER_INFO, (st))
#define M_ASN1_OCTET_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define	sk_Q7_SIGNER_INFO_num(st) SKM_sk_num(Q7_SIGNER_INFO, (st))

/* PKCS#7 ASN1 module */
//#define NID_CN_GM_HASH_SM3			1
//#define NID_CN_GM_ECC				2
#define	NID_q7						3
#define	NID_pkcs7_data				21
#define	NID_q7_data			NID_pkcs7_signed

#define	NID_pkcs7_signed			22
#define	NID_q7_signed				27
#define	NID_q7_data					28
#define	NID_q7_enveloped			6
#define	NID_q7_signedAndEnveloped	7
#define	NID_q7_encrypted			8
#define	NID_q7_dhKeyAgreement		9
//#define	NID_pkcs9_messageDigest		10

#define	NID_q7_digest				11

#define NID_CN_GM_ECDSA_SM3	1501
#define NID_CN_GM_HASH_SM3	1410
#define NID_CN_GM_ECC	1310
#define PKCS7_set_detached_GM(p,v) PKCS7_ctrl_GM(p,PKCS7_OP_SET_DETACHED_SIGNATURE,v,NULL)


#define PKCS7_type_is_signed_GM(a) (OBJ_obj2nid((a)->type) == NID_pkcs7_signed||OBJ_obj2nid((a)->type) == NID_q7_signed)
#define PKCS7_is_detached_GM(p7) (PKCS7_type_is_signed_GM(p7) && PKCS7_get_detached_GM(p7))
#define PKCS7_get_detached_GM(p) \
		PKCS7_ctrl_GM(p,PKCS7_OP_GET_DETACHED_SIGNATURE,0,NULL)


#define PKCS7_SIGNED_GM_ALG	"1.2.156.10197.6.1.4.2.2"	
#define PKCS7_SIGNEDATA_GM_ALG	"1.2.156.10197.6.1.4.2.1"




		
//
///*****************************************************
// *	1.2.156.10197.6.1.4.2	数字信封 OID SM2 GM/T0010       *
// *****************************************************/
//#define SN_q7		"q7"
//#define NID_q7		1513
//#define OBJ_q7		OBJ_CN_GM_ALGOR,513
//
//
//#define LN_q7_data		"q7-data"
//#define NID_q7_data		1514
//#define OBJ_q7_data		OBJ_CN_GM_ALGOR,514
//
//#define LN_q7_signed		"q7-signedData"
//#define NID_q7_signed		1515
//#define OBJ_q7_signed		OBJ_CN_GM_ALGOR,515
//
//#define LN_q7_enveloped		"q7-envelopedData"
//#define NID_q7_enveloped		1516
//#define OBJ_q7_enveloped		OBJ_CN_GM_ALGOR,516
//
//#define LN_q7_signedAndEnveloped		"q7-signedAndEnvelopedData"
//#define NID_q7_signedAndEnveloped		1517
//#define OBJ_q7_signedAndEnveloped		OBJ_CN_GM_ALGOR,517
//
//#define LN_q7_encrypted		"q7-encryptedData"
//#define NID_q7_encrypted		1518
//#define OBJ_q7_encrypted		OBJ_CN_GM_ALGOR,518
//
//#define LN_q7_keyAgreementInfo		"q7-keyAgreementInfo"
#define NID_q7_keyAgreementInfo			1519
//#define OBJ_q7_keyAgreementInfo			OBJ_CN_GM_ALGOR,519
//

///*	1.2.156 			中国	*/
//#define SN_ISO_CN		"ISO-CN"
//#define LN_ISO_CN		"ISO CN Member Body"
//#define NID_ISO_CN		1000
//#define OBJ_ISO_CN		OBJ_member_body,156L
//
///*	1.2.156.10197 		国家密码管理局	*/
//#define SN_CN_GM		"CN-GM"
//#define LN_CN_GM		"CN GuoMi"
//#define NID_CN_GM		1001
//#define OBJ_CN_GM		OBJ_ISO_CN,10197L
//
///*	1.2.156.197.1 		密码算法		*/
//#define SN_CN_GM_ALGOR	"CN-GM-ALGOR"
//#define LN_CN_GM_ALGOR	"CN GuoMi SuanFa"
//#define NID_CN_GM_ALGOR	1010
//#define OBJ_CN_GM_ALGOR	OBJ_CN_GM,1L
//
//
///*****************************************************
// *	1.2.156.197.1.100 	分组密码算法	                       *
// *****************************************************/
//#define SN_CN_GM_BLOCK_CIPHER	"CN-GM-BLOCK-ALGOR"
//#define LN_CN_GM_BLOCK_CIPHER	"CN GuoMi FenZuMiMa SuanFa"
//#define NID_CN_GM_BLOCK_CIPHER	1010
//#define OBJ_CN_GM_BLOCK_CIPHER	OBJ_CN_GM_ALGOR,100
//
///*	1.2.156.197.1.102 	通用SM1/SCB2密码算法	*/
//#define SN_CN_GM_SM1	"CN-GM-SM1"
//#define LN_CN_GM_SM1	"CN GuoMi SM1-TongYong"
//#define NID_CN_GM_SM1	1102
//#define OBJ_CN_GM_SM1	OBJ_CN_GM_ALGOR,102
//
///*	1.2.156.197.1.103 	SSF33密码算法		*/
//#define SN_CN_GM_SSF33	"CN-GM-SSF33"
//#define LN_CN_GM_SSF33	"CN GuoMi SSF33"
//#define NID_CN_GM_SSF33	1103
//#define OBJ_CN_GM_SSF33	OBJ_CN_GM_ALGOR,103
//
///*	1.2.156.197.1.104 	SM4密码算法		*/
//#define SN_CN_GM_SM4	"CN-GM-SM4"
//#define LN_CN_GM_SM4	"CN GuoMi SM4"
//#define NID_CN_GM_SM4	1104
//#define OBJ_CN_GM_SM4	OBJ_CN_GM_ALGOR,104
//
//#define SN_CN_GM_SM4_ECB		"CN-GM-SM4-ECB"
//#define LN_CN_GM_SM4_ECB		"CN GuoMi SM4 ECB"
//#define NID_CN_GM_SM4_ECB		1141
//#define OBJ_CN_GM_SM4_ECB		OBJ_CN_GM_SM4,1
//
//#define SN_CN_GM_SM4_CBC		"CN-GM-SM4-CBC"
//#define LN_CN_GM_SM4_CBC		"CN GuoMi SM4 CBC"
//#define NID_CN_GM_SM4_CBC		1142
//#define OBJ_CN_GM_SM4_CBC		OBJ_CN_GM_SM4,2
//
//
///*****************************************************
// *	1.2.156.197.1.200 	序列密码算法	
// *****************************************************/
//#define SN_CN_GM_STREAM_CIPHER	"CN-GM-STREAM-ALGOR"
//#define LN_CN_GM_STREAM_CIPHER	"CN GuoMi XuLie SuanFa"
//#define NID_CN_GM_STREAM_CIPHER	1200
//#define OBJ_CN_GM_STREAM_CIPHER	OBJ_CN_GM_ALGOR,200
//
//
//
///*****************************************************
// *	1.2.156.197.1.300 	公钥密码算法                 *
// *****************************************************/
//#define SN_CN_GM_PUBKEY_ALGOR	"CN-GM-PUBKEY-ALGOR"
//#define LN_CN_GM_PUBKEY_ALGOR	"CN GM Pubkey Algor"
//#define NID_CN_GM_PUBKEY_ALGOR	1300
//#define OBJ_CN_GM_PUBKEY_ALGOR	OBJ_CN_GM_ALGOR,300
//
///*	1.2.156.197.1.301 	ECC椭圆曲线密码算法		*/
//#define SN_CN_GM_ECC	"CN-GM-ECC"
//#define LN_CN_GM_ECC	"CN GM ECC"
//#define NID_CN_GM_ECC	1310
//#define OBJ_CN_GM_ECC	OBJ_CN_GM_ALGOR,301
//
///*	1.2.156.197.1.301.1 ECC/SM2-1椭圆曲线数字签名算法	*/
//#define SN_CN_GM_ECDSA	"CN-GM-ECDSA"
//#define LN_CN_GM_ECDSA	"CN GM ECDSA"
//#define NID_CN_GM_ECDSA	1311
//#define OBJ_CN_GM_ECDSA	OBJ_CN_GM_ECC,1
//
///*	1.2.156.197.1.301.2 ECC/SM2-2椭圆曲线密钥交换协议	*/
//#define SN_CN_GM_ECDH	"CN-GM-ECDH"
//#define LN_CN_GM_ECDH	"CN GM ECDH"
//#define NID_CN_GM_ECDH	1312
//#define OBJ_CN_GM_ECDH	OBJ_CN_GM_ECC,2
//
///*	1.2.156.197.1.301.3	ECC/SM2-3椭圆曲线加密算法		*/
//#define SN_CN_GM_ECCIPHER	"CN-GM-ECCIPHER"
//#define LN_CN_GM_ECCIPHER	"CN GM ECCIPHER"
//#define NID_CN_GM_ECCIPHER	1313
//#define OBJ_CN_GM_ECCIPHER	OBJ_CN_GM_ECC,3
//
//
//
///*****************************************************
// *	1.2.156.197.1.400 	杂凑算法                                    *
// *****************************************************/
//#define SN_CN_GM_HASH_ALGOR	"CN-GM-HASH-ALGOR"
//#define LN_CN_GM_HASH_ALGOR	"CN GM Hash Algor"
//#define NID_CN_GM_HASH_ALGOR	1400
//#define OBJ_CN_GM_HASH_ALGOR	OBJ_CN_GM_ALGOR,400
//
//
///*	1.2.156.197.1.401 	SM3算法				*/
//#define SN_CN_GM_HASH_SM3	"CN-GM-HASH-SM3"
//#define LN_CN_GM_HASH_SM3	"CN GM SM3 Hash Algor"
//#define NID_CN_GM_HASH_SM3	1410
//#define OBJ_CN_GM_HASH_SM3	OBJ_CN_GM_ALGOR,401
//
///*	1.2.156.197.1.401.1 	SM3无密钥		*/
//#define SN_CN_GM_HASH_SM3_N	"CN-GM-HASH-SM3-N"
//#define LN_CN_GM_HASH_SM3_N	"CN GM SM3 Hash Algor without Key"
//#define NID_CN_GM_HASH_SM3_N	1411
//#define OBJ_CN_GM_HASH_SM3_N	OBJ_CN_GM_HASH_SM3,1
//
///*	1.2.156.197.1.401.2 	SM3有密钥		*/
//#define SN_CN_GM_HASH_SM3_K	"CN-GM-HASH-SM3-K"
//#define LN_CN_GM_HASH_SM3_K	"CN GM SM3 Hash Algor with Key"
//#define NID_CN_GM_HASH_SM3_K	1412
//#define OBJ_CN_GM_HASH_SM3_K	OBJ_CN_GM_HASH_SM3,2
//
//
//
///*****************************************************
// *	1.2.156.197.1.500 	运算机制                     *
// *****************************************************/
//#define SN_CN_GM_ALGOR_METH	"CN-GM-ALGOR-METH"
//#define LN_CN_GM_ALGOR_METH	"CN GM Algor Mechanism"
//#define NID_CN_GM_ALGOR_METH	1500
//#define OBJ_CN_GM_ALGOR_METH	OBJ_CN_GM_ALGOR,500
//
//
///*	1.2.156.197.1.501 	基于ECC算法和SM3/SCH算法的签名		*/
//#define SN_CN_GM_ECDSA_SM3	"CN-GM-ECDSA-SM3"
//#define LN_CN_GM_ECDSA_SM3	"CN GM ECDSA Sign/Verify with SM3"
//#define NID_CN_GM_ECDSA_SM3	1501
//#define OBJ_CN_GM_ECDSA_SM3	OBJ_CN_GM_ALGOR,501
//
///*	1.2.156.197.1.502 	基于ECC算法和SHA-1算法的签名		*/
//#define SN_CN_GM_ECDSA_SHA1	"CN-GM-ECDSA-SHA1"
//#define LN_CN_GM_ECDSA_SHA1	"CN GM ECC Sign/Verify with SHA1"
//#define NID_CN_GM_ECDSA_SHA1	1502
//#define OBJ_CN_GM_ECDSA_SHA1	OBJ_CN_GM_ALGOR,502
//
///*	1.2.156.197.1.503 	基于ECC算法和SHA-1算法的签名		*/
//#define SN_CN_GM_ECDSA_SHA256	"CN-GM-ECDSA-SHA256"
//#define LN_CN_GM_ECDSA_SHA256	"CN GM ECC Sign/Verify with SHA256"
//#define NID_CN_GM_ECDSA_SHA256	1503
//#define OBJ_CN_GM_ECDSA_SHA256	OBJ_CN_GM_ALGOR,503
//
//
//
STACK_OF(PKCS7_SIGNER_INFO) *PKCS7_get_signer_info_GM(PKCS7 *p7);
BIO *PKCS7_Getdata(PKCS7 *p7,int *len);

#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock
#define CRYPTO_w_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_w_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_r_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_r_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_add(addr,amount,type)	\
	CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
#define CRYPTO_w_lock(a)
#define CRYPTO_w_unlock(a)
#define CRYPTO_r_lock(a)
#define CRYPTO_r_unlock(a)
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif





//ASN1_OBJECT IB_nid_objs[11];
//static char IB_nid_data[2][256];

typedef struct q7_issuer_and_serial_st
	{
	X509_NAME *issuer;
	ASN1_INTEGER *serial;
	} Q7_ISSUER_AND_SERIAL;

typedef struct q7_signer_info_st
	{
	ASN1_INTEGER 			*version;	/* version 1 */
	Q7_ISSUER_AND_SERIAL		*issuer_and_serial;
	X509_ALGOR			*digest_alg;
	STACK_OF(X509_ATTRIBUTE)	*auth_attr;	/* [ 0 ] */
	X509_ALGOR			*digest_enc_alg;
	ASN1_OCTET_STRING		*enc_digest;
	STACK_OF(X509_ATTRIBUTE)	*unauth_attr;	/* [ 1 ] */

	/* The private key to sign with */
//	EVP_PKEY			*pkey;
	} Q7_SIGNER_INFO;

DECLARE_STACK_OF(Q7_SIGNER_INFO)
DECLARE_ASN1_SET_OF(Q7_SIGNER_INFO)

typedef struct q7_recip_info_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	Q7_ISSUER_AND_SERIAL		*issuer_and_serial;
	X509_ALGOR			*key_enc_algor;
	ASN1_OCTET_STRING		*enc_key;
	X509				*cert; /* get the pub-key from this */
	} Q7_RECIP_INFO;

DECLARE_STACK_OF(Q7_RECIP_INFO)
DECLARE_ASN1_SET_OF(Q7_RECIP_INFO)

typedef struct q7_content_st
	{

	ASN1_OBJECT *type;
	/* NID_q7_data */
	ASN1_OCTET_STRING *data;

	}Q7_CONTENT; 
DECLARE_STACK_OF(Q7_CONTENT)
DECLARE_ASN1_SET_OF(Q7_CONTENT)
DECLARE_ASN1_FUNCTIONS(Q7_CONTENT)

typedef struct q7_signed_st
	{
	ASN1_INTEGER			*version;	/* version 1 */
	STACK_OF(X509_ALGOR)		*md_algs;	/* md used */
	Q7_CONTENT		*contents;
	STACK_OF(X509)			*cert;		/* [ 0 ] */
	STACK_OF(X509_CRL)		*crl;		/* [ 1 ] */
	STACK_OF(Q7_SIGNER_INFO)	*signer_info;

	} Q7_SIGNED,Q7;
/* The above structure is very very similar to Q7_SIGN_ENVELOPE.
 * How about merging the two */


typedef struct q7_enc_content_st
	{
	ASN1_OBJECT			*content_type;
	X509_ALGOR			*algorithm;
	ASN1_OCTET_STRING		*enc_data;	/* [ 0 ] */
	const EVP_CIPHER		*cipher;
	} Q7_ENC_CONTENT;

typedef struct q7_enveloped_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	STACK_OF(Q7_RECIP_INFO)	*recipientinfo;
	Q7_ENC_CONTENT		*enc_data;
	} Q7_ENVELOPE;

typedef struct q7_signedandenveloped_st
	{
	ASN1_INTEGER			*version;	/* version 1 */
	STACK_OF(X509_ALGOR)		*md_algs;	/* md used */
	STACK_OF(X509)			*cert;		/* [ 0 ] */
	STACK_OF(X509_CRL)		*crl;		/* [ 1 ] */
	STACK_OF(Q7_SIGNER_INFO)	*signer_info;

	Q7_ENC_CONTENT		*enc_data;
	STACK_OF(Q7_RECIP_INFO)	*recipientinfo;
	} Q7_SIGN_ENVELOPE;

typedef struct q7_digest_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	X509_ALGOR			*md;		/* md used */
	struct q7_content_st 		*contents;
	ASN1_OCTET_STRING		*digest;
	} Q7_DIGEST;

typedef struct q7_encrypted_st
	{
	ASN1_INTEGER			*version;	/* version 0 */
	Q7_ENC_CONTENT		*enc_data;
	} Q7_ENCRYPT;


//typedef struct q7_st
//	{
//	/* The following is non NULL if it contains ASN1 encoding of
//	 * this structure */
//	unsigned char *asn1;
//	long length;
//
//#define Q7_S_HEADER	0
//#define Q7_S_BODY	1
//#define Q7_S_TAIL	2
//	int state; /* used during processing */
//
//	int detached;
//
//	ASN1_OBJECT *type;
//	/* content as defined by the type */
//	/* all encryption/message digests are applied to the 'contents',
//	 * leaving out the 'type' field. */
//	union	{
//		char *ptr;
//
//		/* NID_q7_data */
//		ASN1_OCTET_STRING *data;
//
//		/* NID_q7_signed */
//		Q7_SIGNED *sign;
//
//		/* NID_q7_enveloped */
//		Q7_ENVELOPE *enveloped;
//
//		/* NID_q7_signedAndEnveloped */
//		Q7_SIGN_ENVELOPE *signed_and_enveloped;
//
//		/* NID_q7_digest */
//		Q7_DIGEST *digest;
//
//		/* NID_q7_encrypted */
//		Q7_ENCRYPT *encrypted;
//
//		/* Anything else */
//		ASN1_TYPE *other;
//		} d;
//	} Q7;

DECLARE_STACK_OF(Q7)
DECLARE_ASN1_SET_OF(Q7)
DECLARE_PKCS12_STACK_OF(Q7)
/////////////////////////////////GM

//typedef struct pkcs7_gm_st
//	{
//	/* The following is non NULL if it contains ASN1 encoding of
//	 * this structure */
//	unsigned char *asn1;
//	long length;
//
//#define PKCS7_S_HEADER	0
//#define PKCS7_S_BODY	1
//#define PKCS7_S_TAIL	2
//	int state; /* used during processing */
//
//	int detached;
//
//	ASN1_OBJECT *type;
//	/* content as defined by the type */
//	/* all encryption/message digests are applied to the 'contents',
//	 * leaving out the 'type' field. */
//	union	{
//		char *ptr;
//
//		/* NID_pkcs7_data */
//		ASN1_OCTET_STRING *data;
//
//		/* NID_pkcs7_signed */
//		PKCS7_SIGNED *sign;
//
//		/* NID_pkcs7_enveloped */
//		PKCS7_ENVELOPE *enveloped;
//
//		/* NID_pkcs7_signedAndEnveloped */
//		PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
//
//		/* NID_pkcs7_digest */
//		PKCS7_DIGEST *digest;
//
//		/* NID_pkcs7_encrypted */
//		PKCS7_ENCRYPT *encrypted;
//
//		/* Anything else */
//		ASN1_TYPE *other;
//		} d;
//	} PKCS7GM;
//
//DECLARE_STACK_OF(PKCS7GM)
//DECLARE_ASN1_SET_OF(PKCS7GM)
//DECLARE_PKCS12_STACK_OF(PKCS7GM)

#define Q7_OP_SET_DETACHED_SIGNATURE	1
#define Q7_OP_GET_DETACHED_SIGNATURE	2

#define Q7_get_signed_attributes(si)	((si)->auth_attr)
#define Q7_get_attributes(si)	((si)->unauth_attr)

#define Q7_type_is_signed(a) (OBJ_obj2nid((a)->type) == NID_q7_signed)
#define Q7_type_is_encrypted(a) (OBJ_obj2nid((a)->type) == NID_q7_encrypted)
#define Q7_type_is_enveloped(a) (OBJ_obj2nid((a)->type) == NID_q7_enveloped)
#define Q7_type_is_signedAndEnveloped(a) \
		(OBJ_obj2nid((a)->type) == NID_q7_signedAndEnveloped)
#define Q7_type_is_data(a)   (OBJ_obj2nid((a)->type) == NID_q7_data)

#define Q7_type_is_digest(a)   (OBJ_obj2nid((a)->type) == NID_q7_digest)

#define Q7_set_detached(p,v) \
		Q7_ctrl(p,Q7_OP_SET_DETACHED_SIGNATURE,v,NULL)
#define Q7_get_detached(p) \
		Q7_ctrl(p,Q7_OP_GET_DETACHED_SIGNATURE,0,NULL)

#define Q7_is_detached(p7) (Q7_type_is_signed(p7) && Q7_get_detached(p7))

#ifdef SSLEAY_MACROS
#ifndef Q7_ISSUER_AND_SERIAL_digest
#define Q7_ISSUER_AND_SERIAL_digest(data,type,md,len) \
        ASN1_digest((int (*)())i2d_Q7_ISSUER_AND_SERIAL,type,\
	                (char *)data,md,len)
#endif
#endif

/* S/MIME related flags */

#define Q7_TEXT		0x1
#define Q7_NOCERTS		0x2
#define Q7_NOSIGS		0x4
#define Q7_NOCHAIN		0x8
#define Q7_NOINTERN		0x10
#define Q7_NOVERIFY		0x20
#define Q7_DETACHED		0x40
#define Q7_BINARY		0x80
#define Q7_NOATTR		0x100
#define	Q7_NOSMIMECAP	0x200
#define Q7_NOOLDMIMETYPE	0x400
#define Q7_CRLFEOL		0x800
#define Q7_STREAM		0x1000
#define Q7_NOCRL		0x2000

/* Flags: for compatibility with older code */

#define Q7_SMIME_TEXT	Q7_TEXT
#define Q7_SMIME_NOCERTS	Q7_NOCERTS
#define Q7_SMIME_NOSIGS	Q7_NOSIGS
#define Q7_SMIME_NOCHAIN	Q7_NOCHAIN
#define Q7_SMIME_NOINTERN	Q7_NOINTERN
#define Q7_SMIME_NOVERIFY	Q7_NOVERIFY
#define Q7_SMIME_DETACHED	Q7_DETACHED
#define Q7_SMIME_BINARY	Q7_BINARY
#define Q7_SMIME_NOATTR	Q7_NOATTR

DECLARE_ASN1_FUNCTIONS(Q7_ISSUER_AND_SERIAL)

#ifndef SSLEAY_MACROS
int Q7_ISSUER_AND_SERIAL_digest(Q7_ISSUER_AND_SERIAL *data,const EVP_MD *type,
	unsigned char *md,unsigned int *len);
#ifndef OPENSSL_NO_FP_API
Q7 *d2i_Q7_fp(FILE *fp,Q7 **p7);
int i2d_Q7_fp(FILE *fp,Q7 *p7);
#endif
Q7 *Q7_dup(Q7 *p7);
Q7 *d2i_Q7_bio(BIO *bp,Q7 **p7);
int i2d_Q7_bio(BIO *bp,Q7 *p7);
#endif

DECLARE_ASN1_FUNCTIONS(Q7_SIGNER_INFO)
DECLARE_ASN1_FUNCTIONS(Q7_RECIP_INFO)
DECLARE_ASN1_FUNCTIONS(Q7_SIGNED)
DECLARE_ASN1_FUNCTIONS(Q7_ENC_CONTENT)
DECLARE_ASN1_FUNCTIONS(Q7_ENVELOPE)
DECLARE_ASN1_FUNCTIONS(Q7_SIGN_ENVELOPE)
DECLARE_ASN1_FUNCTIONS(Q7_DIGEST)
DECLARE_ASN1_FUNCTIONS(Q7_ENCRYPT)
DECLARE_ASN1_FUNCTIONS(Q7)

DECLARE_ASN1_ITEM(Q7_ATTR_SIGN)
DECLARE_ASN1_ITEM(Q7_ATTR_VERIFY)

DECLARE_ASN1_NDEF_FUNCTION(Q7)

static int add_attribute(STACK_OF(X509_ATTRIBUTE) **sk, int nid, int atrtype,
			 void *value);
static ASN1_TYPE *get_attribute(STACK_OF(X509_ATTRIBUTE) *sk, int nid);

int do_q7_signed_attrib(Q7_SIGNER_INFO *si,unsigned char* hash, int hashlen);

long Q7_ctrl(Q7 *p7, int cmd, long larg, char *parg);
int Q7_SIGNER_INFO_set(Q7_SIGNER_INFO *p7i, X509 *x509);

int Q7_set_type(Q7 *p7, int type);
int Q7_set0_type_other(Q7 *p7, int type, ASN1_TYPE *other);
int Q7_set_content(Q7 *p7, Q7 *p7_data);
int Q7_add_signer(Q7 *p7, Q7_SIGNER_INFO *p7i);
int Q7_add_certificate(Q7 *p7, X509 *x509);
int Q7_add_crl(Q7 *p7, X509_CRL *x509);
int Q7_content_new(Q7 *p7, int nid);
int Q7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx,
	BIO *bio, Q7 *p7, Q7_SIGNER_INFO *si); 
int Q7_signatureVerify(BIO *bio, Q7 *p7, Q7_SIGNER_INFO *si,
								X509 *x509);

BIO *Q7_dataInit(Q7 *p7, BIO *bio);
int Q7_dataFinal(Q7 *p7, BIO *bio);
BIO *Q7_dataDecode(Q7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);


Q7_SIGNER_INFO *Q7_add_signature(Q7 *p7, X509 *x509);
X509 *Q7_cert_from_signer_info(Q7 *p7, Q7_SIGNER_INFO *si);
int Q7_set_digest(Q7 *p7, const EVP_MD *md);
STACK_OF(Q7_SIGNER_INFO) *Q7_get_signer_info(Q7 *p7);

Q7_RECIP_INFO *Q7_add_recipient(Q7 *p7, X509 *x509);
int Q7_add_recipient_info(Q7 *p7, Q7_RECIP_INFO *ri);
int Q7_RECIP_INFO_set(Q7_RECIP_INFO *p7i, X509 *x509);
int Q7_set_cipher(Q7 *p7, const EVP_CIPHER *cipher);

Q7_ISSUER_AND_SERIAL *Q7_get_issuer_and_serial(Q7 *p7, int idx);
ASN1_OCTET_STRING *Q7_digest_from_attributes(STACK_OF(X509_ATTRIBUTE) *sk);
int Q7_add_signed_attribute(Q7_SIGNER_INFO *p7si,int nid,int type,
	void *data);
int Q7_add_attribute (Q7_SIGNER_INFO *p7si, int nid, int atrtype,
	void *value);
ASN1_TYPE *Q7_get_attribute(Q7_SIGNER_INFO *si, int nid);
ASN1_TYPE *Q7_get_signed_attribute(Q7_SIGNER_INFO *si, int nid);
int Q7_set_signed_attributes(Q7_SIGNER_INFO *p7si,
				STACK_OF(X509_ATTRIBUTE) *sk);
int Q7_set_attributes(Q7_SIGNER_INFO *p7si,STACK_OF(X509_ATTRIBUTE) *sk);


Q7 *Q7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
							BIO *data, int flags);
int Q7_verify(Q7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
					BIO *indata, BIO *out, int flags);
STACK_OF(X509) *Q7_get0_signers(Q7 *p7, STACK_OF(X509) *certs, int flags);
Q7 *Q7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
								int flags);
int Q7_decrypt(Q7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags);

int Q7_add_attrib_smimecap(Q7_SIGNER_INFO *si,
			      STACK_OF(X509_ALGOR) *cap);
STACK_OF(X509_ALGOR) *Q7_get_smimecap(Q7_SIGNER_INFO *si);
int Q7_simple_smimecap(STACK_OF(X509_ALGOR) *sk, int nid, int arg);

int SMIME_write_Q7(BIO *bio, Q7 *p7, BIO *data, int flags);
Q7 *SMIME_read_Q7(BIO *bio, BIO **bcont);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_Q7_strings(void);

/* Error codes for the Q7 functions. */

/* Function codes. */
#define Q7_F_B64_READ_Q7				 120
#define Q7_F_B64_WRITE_Q7				 121
#define Q7_F_Q7_ADD_ATTRIB_SMIMECAP		 118
#define Q7_F_Q7_ADD_CERTIFICATE			 100
#define Q7_F_Q7_ADD_CRL				 101
#define Q7_F_Q7_ADD_RECIPIENT_INFO		 102
#define Q7_F_Q7_ADD_SIGNER			 103
#define Q7_F_Q7_BIO_ADD_DIGEST			 125
#define Q7_F_Q7_CTRL				 104
#define Q7_F_Q7_DATADECODE			 112
#define Q7_F_Q7_DATAFINAL				 128
#define Q7_F_Q7_DATAINIT				 105
#define Q7_F_Q7_DATASIGN				 106
#define Q7_F_Q7_DATAVERIFY			 107
#define Q7_F_Q7_DECRYPT				 114
#define Q7_F_Q7_ENCRYPT				 115
#define Q7_F_Q7_FIND_DIGEST			 127
#define Q7_F_Q7_GET0_SIGNERS			 124
#define Q7_F_Q7_SET_CIPHER			 108
#define Q7_F_Q7_SET_CONTENT			 109
#define Q7_F_Q7_SET_DIGEST			 126
#define Q7_F_Q7_SET_TYPE				 110
#define Q7_F_Q7_SIGN				 116
#define Q7_F_Q7_SIGNATUREVERIFY			 113
#define Q7_F_Q7_SIMPLE_SMIMECAP			 119
#define Q7_F_Q7_VERIFY				 117
#define Q7_F_SMIME_READ_Q7			 122
#define Q7_F_SMIME_TEXT				 123

/* Reason codes. */
#define Q7_R_CERTIFICATE_VERIFY_ERROR		 117
#define Q7_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER		 144
#define Q7_R_CIPHER_NOT_INITIALIZED			 116
#define Q7_R_CONTENT_AND_DATA_PRESENT		 118
#define Q7_R_DECODE_ERROR				 130
#define Q7_R_DECRYPTED_KEY_IS_WRONG_LENGTH		 100
#define Q7_R_DECRYPT_ERROR				 119
#define Q7_R_DIGEST_FAILURE				 101
#define Q7_R_ERROR_ADDING_RECIPIENT			 120
#define Q7_R_ERROR_SETTING_CIPHER			 121
#define Q7_R_INVALID_MIME_TYPE			 131
#define Q7_R_INVALID_NULL_POINTER			 143
#define Q7_R_MIME_NO_CONTENT_TYPE			 132
#define Q7_R_MIME_PARSE_ERROR			 133
#define Q7_R_MIME_SIG_PARSE_ERROR			 134
#define Q7_R_MISSING_CERIPEND_INFO			 103
#define Q7_R_NO_CONTENT				 122
#define Q7_R_NO_CONTENT_TYPE				 135
#define Q7_R_NO_MULTIPART_BODY_FAILURE		 136
#define Q7_R_NO_MULTIPART_BOUNDARY			 137
#define Q7_R_NO_RECIPIENT_MATCHES_CERTIFICATE	 115
#define Q7_R_NO_RECIPIENT_MATCHES_KEY		 146
#define Q7_R_NO_SIGNATURES_ON_DATA			 123
#define Q7_R_NO_SIGNERS				 142
#define Q7_R_NO_SIG_CONTENT_TYPE			 138
#define Q7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE	 104
#define Q7_R_Q7_ADD_SIGNATURE_ERROR		 124
#define Q7_R_Q7_DATAFINAL				 126
#define Q7_R_Q7_DATAFINAL_ERROR			 125
#define Q7_R_Q7_DATASIGN				 145
#define Q7_R_Q7_PARSE_ERROR			 139
#define Q7_R_Q7_SIG_PARSE_ERROR			 140
#define Q7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE	 127
#define Q7_R_SIGNATURE_FAILURE			 105
#define Q7_R_SIGNER_CERTIFICATE_NOT_FOUND		 128
#define Q7_R_SIG_INVALID_MIME_TYPE			 141
#define Q7_R_SMIME_TEXT_ERROR			 129
#define Q7_R_UNABLE_TO_FIND_CERTIFICATE		 106
#define Q7_R_UNABLE_TO_FIND_MEM_BIO			 107
#define Q7_R_UNABLE_TO_FIND_MESSAGE_DIGEST		 108
#define Q7_R_UNKNOWN_DIGEST_TYPE			 109
#define Q7_R_UNKNOWN_OPERATION			 110
#define Q7_R_UNSUPPORTED_CIPHER_TYPE			 111
#define Q7_R_UNSUPPORTED_CONTENT_TYPE		 112
#define Q7_R_WRONG_CONTENT_TYPE			 113
#define Q7_R_WRONG_Q7_TYPE			 114

#ifdef  __cplusplus
}
#endif
#endif
