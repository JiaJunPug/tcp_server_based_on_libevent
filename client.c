#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "SVSRequest.h"
#include "SVSRespond.h"
#include "sign_verify_server.h"
#define NUM_ 1
static int g_type = 0;
#define ZEDD
#ifdef ZEDD
#define zed(format, args...) printf("[%s][%s][%d] "format"", __FILE__, __func__, __LINE__, ##args)
#else
#define zed(format, args...)
#endif
static void *thread_fun(void *arg)
{
	int ret=0;
	SignDataResp respond;
	bzero(&respond, sizeof(respond));
	struct timeval tv_begin, tv_end;
	int cnt = 0;
	int a = 0x00020201;
	int b = 1;
	char *c = "df6b744a43c541ae8dd438531cbd024b";
	int d = 2728;
	char *e = "/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////01JSUM5ekNDQXB5Z0F3SUJBZ0lIQXpNUUFBRmdtREFNQmdncWdSelBWUUdEZFFVQU1ENHhDekFKQmdOVkJBWVRBa05PTVI0d0hBWURWUVFLREJYbXNaL29pNC9ubklIbmxMWGxyWkRtbEwvbGlxRXhEekFOQmdOVkJBTU1Ca05CWDFOTk1qQWVGdzB4T1RFeU1Ua3dOelE1TXpKYUZ3MHlNakV5TVRrd056UTVNekphTUlHVE1Rc3dDUVlEVlFRR0V3SkRUakVOTUFzR0ExVUVCd3dFU2xOU1FURWJNQmtHQTFVRUNnd1M1TGlBNklpczU1U3o2SyszNVkyVjVMMk5NUnd3R2dZSktvWklodmNOQVFrQkZnMXdNVEJBWlcxaGFXd3VZMjl0TVNjd0pRWURWUVFwREI1S1V6QXdNakF4T1RFeU1Ua3hOVE0zTXpZd01EQXhNREF3TVc1MWJHd3hFVEFQQmdOVkJBTU1DSE50TWkxallYSmtNRmt3RXdZSEtvWkl6ajBDQVFZSUtvRWN6MVVCZ2kwRFFnQUVrbUwvQ3dja0M0Lzc4eFNUZzNqVVBERFpqdUNBOVBJKzFaOFdUc2EzT1hJTXhnd0x2Y3N4RGtSL3NqNjk5bW5SNEZ4eU1rdEpreFI2UjhhRnA1YksxYU9DQVNzd2dnRW5NQmdHQTFVZEVRUVJNQStCRFhBeE1FQmxiV0ZwYkM1amIyMHdNUVlEVlIwZkJDb3dLREFtb0NTZ0lvWWdhSFIwY0Rvdkx6RTNNaTR4TmpndU15NHpMMHBUV2xkRFFWTk5NaTVqY213d0h3WURWUjBqQkJnd0ZvQVUybWpyNlc4T1JxQXJvQ1loelp6ZGJGYzR6UTh3SFFZRFZSME9CQllFRkhrMG9ZUE9JbU04aVlBa1VCMVBxVWRhc3h5aU1BNEdBMVVkRHdFQi93UUVBd0lHd0RBTUJnTlZIUk1FQlRBREFRRUFNQjhHQ0NxQkhOQVVCQUVCQkJPZ0VSTVBNVEV4TVRFeE1URXhNVFUxTlRVMU1Ed0dDQ3NHQVFVRkJ3RUJCREF3TGpBc0JnZ3JCZ0VGQlFjd0FvWWdhSFIwY0Rvdkx6RTNNaTR4TmpndU15NHpMMHBUV2xkRFFWTk5NaTVqWlhJd0d3WUpLd1lCQkFHQ054UUNCQTRNRE9pdXZ1V2toK2l2Z2VTNXBqQU1CZ2dxZ1J6UFZRR0RkUVVBQTBjQU1FUUNJQWxFcUJNQkFqbVUrb2xoelJsbm9qMFJzeWNzaXpiRUhLMjEzMzYwNE5PdEFpQnpody9rSDdKS21lMiszbjFtQkNJNENObjJCcVdsbXd5TFI5V0ZuMEk5SVE9PQ==";
	printf("strlen(e) = %d\n", strlen(e));
	gettimeofday(&tv_begin, NULL);
	while (cnt>0) {
		ret = Mid_SignData(a, b, c, d, e, &respond);
		//printf("ret = %d\n", ret);
		cnt--;
	}
	gettimeofday(&tv_end, NULL);
	printf("[%s:%d] interval [%.6fs]\n", __func__, __LINE__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
	float f = tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001;
//	printf("%f\n", 1000/0.2);
	printf("%f/s\n", 1000*1.0/f);
	int id;
	int fd;
	int flag = true, no_flag = false;
	struct sockaddr_in serv_addr;
	char str[] = "1";
	unsigned char data[32];
	char recv[2048] = "";

	SVSRequest_t *req = NULL;
	SVSRespond_t *res = NULL;
	int err = 0;
	time_t now;
	struct tm *cur_tm;
//	unsigned char buf[1024];
//	int len = sizeof(buf);
	unsigned char *buf=(unsigned char *)calloc(1, 4096);
	int len = 4096;
	FILE *pf = NULL;
	asn_enc_rval_t ec;
	asn_enc_rval_t enc_ret;
	asn_dec_rval_t dec_ret;

	unsigned char cert[2048];
	int cert_len = 2048;
	unsigned char cert_64[4096]="";
	int cert_64_len = sizeof(cert_64);
	Certificate_t *x = NULL;
	FILE *fp = NULL;
	//fp = fopen("cert.cer", "rb");
	fp = fopen("cert.cer", "rb");
	if (fp) {
		cert_len = fread(cert, 1, 2048, fp);
		printf("cert_len = %d\n", cert_len);
//		ret = base64_encode(cert_64, &cert_64_len, cert, cert_len);
//		printf("base64_decode ret = %d, cert_64_len = %d\n", ret, cert_64_len);
		fclose(fp);
	}

	//if (arg) {
	//	free(arg);
	//}

	req = (SVSRequest_t*)calloc(1, sizeof(SVSRequest_t));
	if (!req) {
		perror("calloc failed");
		exit(1);
	}
	req->version = 0;
	if (g_type == ReqType_exportCert) {
		req->reqType = ReqType_exportCert;
		req->request.present = Request_PR_exportCertReq;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.exportCertReq.identification, str, strlen(str))) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_getServerCertificate) {
		req->reqType = ReqType_getServerCertificate;
		req->request.present = Request_PR_getServerCertificateReq;
		req->request.choice.getServerCertificateReq.certUsage = 2;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.getServerCertificateReq.containerName, str, strlen(str))) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_parseCert) {
		dec_ret = ber_decode(NULL, &asn_DEF_Certificate, &x, cert, cert_len);
		zed("dec_ret.code = %d\n", dec_ret.code);
		req->reqType = ReqType_parseCert;
		req->request.present = Request_PR_parseCertReq;
		req->request.choice.parseCertReq.infoType = SGD_CERT_SUBJECT_O;
		memcpy(&req->request.choice.parseCertReq.cert, x, sizeof(Certificate_t));
	} else if (g_type == ReqType_genRandom) {
		req->reqType = ReqType_genRandom;
		req->request.present = Request_PR_genRandomReq;
		req->request.choice.genRandomReq.randomLen = 16;
	} else if (g_type == ReqType_getCertInfoByOid) {
	//	char *oid = "1.2.156.10260.4.1.1";
		char *oid = "1.3.6.1.4.1.311.20.2";
		req->reqType = ReqType_getCertInfoByOid;
		req->request.present = Request_PR_getCertInfoByOidReq;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.getCertInfoByOidReq.base64EncodeCert, cert_64, cert_64_len)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.getCertInfoByOidReq.oid, oid, strlen(oid))) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_encryptData) {
		unsigned char *data = "abcdefghij123456abababababababab";
		req->reqType = ReqType_encryptData;
		req->request.present = Request_PR_encryptDataReq;
		req->request.choice.encryptDataReq.symMethod = 0x00000408;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.encryptDataReq.cert, cert, cert_len)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.encryptDataReq.inData, data, strlen(data))) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_decryptData) {
		char data[4096];
		int d_len = sizeof(data);
		fp = fopen("encrypt", "r");
		d_len = fread(data, 1, sizeof(data), fp);
		fclose(fp);
		printf("d_len = %d\n", d_len);
		req->reqType = ReqType_decryptData;
		req->request.present = Request_PR_decryptDataReq;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.decryptDataReq.containerName, str, 1)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.decryptDataReq.inData, data, d_len)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_createTimeStampRequest) {
		unsigned char *data = "abcdefghij123456abababababababab";
		req->reqType = ReqType_createTimeStampRequest;
		req->request.present = Request_PR_createTimeStampRequestReq;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.createTimeStampRequestReq.inData, data, strlen(data))) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		req->request.choice.createTimeStampRequestReq.hashMethod = SGD_SM3;
		req->request.choice.createTimeStampRequestReq.certReq = 1;
		req->request.choice.createTimeStampRequestReq.nonce = 0;
	} else if (g_type == ReqType_createTimeStampResponse) {
		printf("*******%s %d********\n", __func__, __LINE__);
		fp = fopen("tsrequest", "r");
		ret = fread(cert_64, 1, cert_64_len, fp);
		printf("fread ret = %d\n", ret);
		fclose(fp);
		req->reqType = ReqType_createTimeStampResponse;
		req->request.present = Request_PR_createTimeStampResponseReq;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.createTimeStampResponseReq.timeStampRequest, cert_64, ret)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.createTimeStampResponseReq.containerName, str, 1)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_verifyTimeStamp) {
		unsigned char *data = "abcdefghij123456abababababababab";
		req->reqType = ReqType_verifyTimeStamp;
		req->request.present = Request_PR_verifyTimeStampReq;
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.verifyTimeStampReq.inData, data, strlen(data))) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		fp = fopen("tsresponse", "r");
		ret = fread(cert_64, 1, cert_64_len, fp);
		printf("fread ret = %d\n", ret);
		fclose(fp);
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.verifyTimeStampReq.tsResponseData, cert_64, ret)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
	} else if (g_type == ReqType_getTimeStampInfo) {
		unsigned char ggg[4096]="";
		int ggg_len = sizeof(ggg);
		req->reqType = ReqType_getTimeStampInfo;
		req->request.present = Request_PR_getTimeStampInfoReq;
		fp = fopen("tsresponse", "r");
		cert_64_len = fread(cert_64, 1, cert_64_len, fp);
		printf("fread ret = %d\n", cert_64_len);
		fclose(fp);
		ret = base64_encode(ggg, &ggg_len, cert_64, cert_64_len);
		printf("base64_decode ret = %d, ggg_len = %d\n", ret, ggg_len);
		if ((err = OCTET_STRING_fromBuf(&req->request.choice.getTimeStampInfoReq.tsResponseData, ggg, ggg_len)) != 0) {
			fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        	exit(2);
		}
		req->request.choice.getTimeStampInfoReq.type = 3;
	}
#if 0
	char keyvalue[] = "df6b744a43c541ae8dd438531cbd024b";
#if 1
	char indata[1024*1024*2 - 123];
#else
	char indata[10];
#endif
	memset(indata, 0xBB, sizeof(indata));
	req->reqType = ReqType_signData;
	req->request.present = Request_PR_signDataReq;
	req->request.choice.signDataReq.signMethod = SGD_SM3_SM2;
	req->request.choice.signDataReq.keyIndex = 1;
	OCTET_STRING_fromBuf(&req->request.choice.signDataReq.keyValue, keyvalue, strlen(keyvalue));
	req->request.choice.signDataReq.inDataLen = sizeof(indata);
	OCTET_STRING_fromBuf(&req->request.choice.signDataReq.inData, indata, strlen(indata));
	dec_ret = ber_decode(NULL, &asn_DEF_Certificate, &x, cert, cert_len);
	zed("dec_ret.code = %d\n", dec_ret.code);
	req->reqType = ReqType_validateCert;
	req->request.present = Request_PR_validateCertReq;
	req->request.choice.validateCertReq.ocsp = &flag;
	memcpy(&req->request.choice.validateCertReq.cert, x, sizeof(Certificate_t));
	long val_long = 0;
	char strs[] = "12345678";
	memset(data, 0xff, sizeof(data));
	dec_ret = ber_decode(NULL, &asn_DEF_Certificate, &x, cert, cert_len);
	zed("dec_ret.code = %d\n", dec_ret.code);
	req->reqType = ReqType_verifySignedData;
	req->request.present = Request_PR_verifySignedDataReq;
	req->request.choice.verifySignedDataReq.type = val_long;
	req->request.choice.verifySignedDataReq.cert = x;
	//req->request.choice.verifySignedDataReq.certSN = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, data, sizeof(data));
	req->request.choice.verifySignedDataReq.certSN = OCTET_STRING_new_fromBuf(&asn_DEF_SVSRequest, data, sizeof(data));
	req->request.choice.verifySignedDataReq.inDataLen = 8;
	if (OCTET_STRING_fromBuf(&req->request.choice.verifySignedDataReq.inData, strs, strlen(strs)) != 0) {
		zed("asdasdasd\n");
		exit(1);
	}
	if (OCTET_STRING_fromBuf(&req->request.choice.verifySignedDataReq.signature, strs, strlen(strs)) != 0) {
		zed("asdasdasd\n");
		exit(1);
	}
	req->request.choice.verifySignedDataReq.verifyLevel = 0;
	char keyvalue[] = "df6b744a43c541ae8dd438531cbd024b";
	char indata[1600];
	memset(indata, 0xaa, sizeof(indata));
	req->reqType = ReqType_signMessage;
	req->request.present = Request_PR_signMessageReq;
	req->request.choice.signMessageReq.signMethod = SGD_SM3_SM2;
	req->request.choice.signMessageReq.keyIndex = 1;
	if (OCTET_STRING_fromBuf(&req->request.choice.signMessageReq.keyValue, keyvalue, strlen(keyvalue)) != 0) {
		zed("asdasdasd\n");
		exit(1);
	}
	if (OCTET_STRING_fromBuf(&req->request.choice.signMessageReq.inData, indata, strlen(indata)) != 0) {
		zed("asdasdasd\n");
		exit(1);
	}
	zed("req->request.choice.signMessageReq.inData.size = %d\n", req->request.choice.signMessageReq.inData.size);
	req->request.choice.signMessageReq.inDataLen = req->request.choice.signMessageReq.inData.size;
	req->request.choice.signMessageReq.hashFlag = &no_flag;
	req->request.choice.signMessageReq.originalText = &no_flag;
	req->request.choice.signMessageReq.certificateChain = &flag;
	req->request.choice.signMessageReq.crl = &no_flag;
	req->request.choice.signMessageReq.authenticationAttributes = &no_flag;
	#if 0
	req->reqType = ReqType_getCertTrustListAltNames;
	req->request.present = Request_PR_getCertTrustListAltNamesReq;
//	if ((err = OCTET_STRING_fromBuf(&req->request.choice.exportCertReq.identification, str, strlen(str))) != 0) {
//		fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
  //      exit(2);
//	}
#else
#if 0
	req->request.choice.setCertTrustListReq.ctlContentLen = strlen(c);
	req->reqType = ReqType_setCertTrustList;
	req->request.present = Request_PR_setCertTrustListReq;
	if ((err = OCTET_STRING_fromBuf(&req->request.choice.setCertTrustListReq.ctlAltName, str, strlen(str))) != 0) {
		fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        exit(2);
	}
	if ((err = OCTET_STRING_fromBuf(&req->request.choice.setCertTrustListReq.ctlContent, c, strlen(c))) != 0) {
		fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        exit(2);
	}
	req->reqType = ReqType_getCertTrustList;
	req->request.present = Request_PR_getCertTrustListReq;
	if ((err = OCTET_STRING_fromBuf(&req->request.choice.getCertTrustListReq.ctlAltName, str, strlen(str))) != 0) {
		fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        exit(2);
	}
#else
	req->reqType = ReqType_delCertTrustList;
	req->request.present = Request_PR_delCertTrustListReq;
	if ((err = OCTET_STRING_fromBuf(&req->request.choice.delCertTrustListReq.ctlAltName, str, strlen(str))) != 0) {
		fprintf(stderr, "OCTET_STRING_fromString() failed, return: %d\n", err);
        exit(2);
	}
#endif
#endif
#endif

	now = time(NULL);
	cur_tm = localtime(&now);
	asn_time2GT(&req->reqTime, cur_tm, 1);

	ec = der_encode_to_buffer(&asn_DEF_SVSRequest, req, buf, len);
	zed("ec.encoded = %d\n", ec.encoded);
    if(ec.encoded  == -1) {
        fprintf(stderr, "Could not encode SVSRequest (at %s)\n", ec.failed_type ? ec.failed_type->name : "unknown");
		bzero(buf, len);
        exit(3);
    }
	int i=0;
	for (i=0; i<20; i++)
		printf("%02X ", buf[i]);
	printf("\n*************\n");

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return NULL;
	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(9996);
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//	ret = setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
//	zed("setsockopt ret = %d\n", ret);

	ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr));
	if (ret < 0)
		return NULL;

	ret = write(fd, buf, ec.encoded);
	zed("write ret = %d\n", ret);
	
	/*for response*/
	ret = read(fd, recv, sizeof(recv));
	zed("recv ret = %d str = %s\n", ret, recv);
	dec_ret = ber_decode(NULL, &asn_DEF_SVSRespond, (void **)&res, recv, ret);
	zed("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code == RC_OK) {
		printf("\n ----- decode successful-----\n");
		printf("version: %d\n", res->version);
		printf("reqType: %d\n", res->respType);
		if (res->respond.present == Respond_PR_exportCertResp) {
			printf(" export_cert respone: %ld\n", res->respond.choice.exportCertResp.respValue);
			char buff[2048] = "";
			int buff_len = sizeof(buff);
			enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, res->respond.choice.exportCertResp.cert, buff, buff_len);
			zed("enc_ret.encoded = %d\n", enc_ret.encoded);
			fp = fopen("cert.cer", "wb");
			if (fp) {
				cert_len = fwrite(buff, 1, enc_ret.encoded, fp);
				printf("cert_len = %d\n", cert_len);
				fclose(fp);
			}

		} else if (res->respond.present == Respond_PR_parseCertResp) {
			int i=0;
			asn_dec_rval_t dec_ret_2;
			printf(" parse_cert respone: %ld\n", res->respond.choice.parseCertResp.respValue);
			printf(" parse_cert info: %d\n", res->respond.choice.parseCertResp.info->size);
		//	for (i=0; i<res->respond.choice.parseCertResp.info->size; i++)
		//		printf("%02x ", res->respond.choice.parseCertResp.info->buf[i]);
		//	printf("\n");

			//printf(" parse_cert info: %ld\n", *(long *)(res->respond.choice.parseCertResp.info->buf));
			printf(" parse_cert info: %s\n", (res->respond.choice.parseCertResp.info->buf));
//			dec_ret_2 = ber_decode(NULL, &asn_DEF_OCTET_STRING, (void **)&res->respond.choice.parseCertResp.info, ff, 128);
		} else if (res->respond.present == Respond_PR_validateCertResp) {
			printf(" valid_cert respone: %ld\n", res->respond.choice.validateCertResp.respValue);
			printf(" valid_cert state: %ld\n", *(res->respond.choice.validateCertResp.state));
		} else if (res->respond.present == Respond_PR_signMessageResp) {
			printf(" signmessage respone: %ld\n", res->respond.choice.signMessageResp.respValue);
			printf(" signmessage signedMessage buf: %s\n", res->respond.choice.signMessageResp.signedMessage->buf);
			printf(" signmessage signedMessage size: %d\n", res->respond.choice.signMessageResp.signedMessage->size);
		} else if (res->respond.present == Respond_PR_signDataResp) {
			printf(" signmessage respone: %ld\n", res->respond.choice.signDataResp.respValue);
			printf(" signmessage signedMessage buf: %s\n", res->respond.choice.signDataResp.signature->buf);
			printf(" signmessage signedMessage size: %d\n", res->respond.choice.signDataResp.signature->size);
		} else if (res->respond.present == Respond_PR_getCertTrustListAltNamesResp) {
			printf(" signmessage respone: %ld\n", res->respond.choice.getCertTrustListAltNamesResp.respValue);
			printf(" signmessage ctlAltNames buf: %s\n", res->respond.choice.getCertTrustListAltNamesResp.ctlAltNames->buf);
		} else if (res->respond.present == Respond_PR_setCertTrustListResp) {
			printf(" setCertTrustList respone: %08x\n", res->respond.choice.setCertTrustListResp.respValue);
		} else if (res->respond.present == Respond_PR_getCertTrustListResp) {
			printf(" signmessage respone: %ld\n", res->respond.choice.getCertTrustListResp.respValue);
			printf(" signmessage ctlAltNames buf: %s\n", res->respond.choice.getCertTrustListResp.ctlContent->buf);
		} else if (res->respond.present == Respond_PR_delCertTrustListResp) {
			printf(" delCertTrustList respone: %08x\n", res->respond.choice.delCertTrustListResp.respValue);
		} else if (res->respond.present == Respond_PR_getServerCertificateResp) {
			printf(" getServerCertificate respone: %ld\n", res->respond.choice.getServerCertificateResp.respValue);
			printf(" getServerCertificate buf: %s\n", res->respond.choice.getServerCertificateResp.cert->buf);
			fp = fopen("cert.cer", "wb");
			fwrite(res->respond.choice.getServerCertificateResp.cert->buf, 1, res->respond.choice.getServerCertificateResp.cert->size, fp);
			fclose(fp);
		} else if (res->respond.present == Respond_PR_genRandomResp) {
			printf(" genRandomResp respone: %ld\n", res->respond.choice.genRandomResp.respValue);
			printf(" genRandomResp size: %d\n", res->respond.choice.genRandomResp.random?res->respond.choice.genRandomResp.random->size:0);
			printf(" genRandomResp buf: %s\n", res->respond.choice.genRandomResp.random?res->respond.choice.genRandomResp.random->buf:"NULL");
		} else if (res->respond.present == Respond_PR_getCertInfoByOidResp) {
			printf(" getCertInfoByOid respone: %ld\n", res->respond.choice.getCertInfoByOidResp.respValue);
			printf(" getCertInfoByOid size: %d\n", res->respond.choice.getCertInfoByOidResp.info?res->respond.choice.getCertInfoByOidResp.info->size:0);
			printf(" getCertInfoByOid buf: %s\n", res->respond.choice.getCertInfoByOidResp.info?res->respond.choice.getCertInfoByOidResp.info->buf:"NULL");
		} else if (res->respond.present == Respond_PR_encryptDataResp) {
			printf(" encryptDataResp respone: %ld\n", res->respond.choice.encryptDataResp.respValue);
			printf(" encryptDataResp size: %d\n", res->respond.choice.encryptDataResp.outData?res->respond.choice.encryptDataResp.outData->size:0);
			printf(" encryptDataResp buf: %s\n", res->respond.choice.encryptDataResp.outData?res->respond.choice.encryptDataResp.outData->buf:"NULL");
			fp = fopen("encrypt", "wb");
			fwrite(res->respond.choice.encryptDataResp.outData->buf, 1, res->respond.choice.encryptDataResp.outData->size, fp);
			fclose(fp);
		} else if (res->respond.present == Respond_PR_decryptDataResp) {
			printf(" decryptDataResp respone: %ld\n", res->respond.choice.decryptDataResp.respValue);
			printf(" decryptDataResp size: %d\n", res->respond.choice.decryptDataResp.outData?res->respond.choice.decryptDataResp.outData->size:0);
			printf(" decryptDataResp buf: %s\n", res->respond.choice.decryptDataResp.outData?res->respond.choice.decryptDataResp.outData->buf:"NULL");
		} else if (res->respond.present == Respond_PR_createTimeStampRequestResp) {
			printf(" createTimeStampRequestResp respone: %ld\n", res->respond.choice.createTimeStampRequestResp.respValue);
			printf(" createTimeStampRequestResp size: %d\n", res->respond.choice.createTimeStampRequestResp.outData?res->respond.choice.createTimeStampRequestResp.outData->size:0);
			printf(" createTimeStampRequestResp buf: %s\n", res->respond.choice.createTimeStampRequestResp.outData?res->respond.choice.createTimeStampRequestResp.outData->buf:"NULL");
			ret = base64_decode(cert_64, &cert_64_len, res->respond.choice.createTimeStampRequestResp.outData->buf, res->respond.choice.createTimeStampRequestResp.outData->size);
			printf("base64_decode ret=%d|cert_64_len = %d\n", cert_64_len);
			fp = fopen("tsrequest", "wb");
			fwrite(cert_64, 1, cert_64_len, fp);
			fclose(fp);
		} else if (res->respond.present == Respond_PR_createTimeStampResponseResp) {
			printf(" createTimeStampResponseResp respone: %ld\n", res->respond.choice.createTimeStampResponseResp.respValue);
			printf(" createTimeStampResponseResp size: %d\n", res->respond.choice.createTimeStampResponseResp.outData?res->respond.choice.createTimeStampResponseResp.outData->size:0);
			printf(" createTimeStampResponseResp buf: %s\n", res->respond.choice.createTimeStampResponseResp.outData?res->respond.choice.createTimeStampResponseResp.outData->buf:"NULL");
			ret = base64_decode(cert_64, &cert_64_len, res->respond.choice.createTimeStampResponseResp.outData->buf, res->respond.choice.createTimeStampResponseResp.outData->size);
			printf("base64_decode ret=%d|cert_64_len = %d\n", cert_64_len);
			fp = fopen("tsresponse", "wb");
			fwrite(cert_64, 1, cert_64_len, fp);
			fclose(fp);
		} else if (res->respond.present == Respond_PR_verifyTimeStampResp) {
			printf(" verifyTimeStampResp respone: %ld\n", res->respond.choice.verifyTimeStampResp.respValue );
		} else if (res->respond.present == Respond_PR_getTimeStampInfoResp) {
			printf(" getTimeStampInfoResp respone: %ld\n", res->respond.choice.getTimeStampInfoResp.respValue );
			printf(" getTimeStampInfoResp size: %ld\n", res->respond.choice.getTimeStampInfoResp.info? res->respond.choice.getTimeStampInfoResp.info->size : 0);
			printf(" getTimeStampInfoResp buf: %s\n", res->respond.choice.getTimeStampInfoResp.info? res->respond.choice.getTimeStampInfoResp.info->buf : "NULL");
			FILE *fp = fopen("timestamp_cert", "wb");
			fwrite(res->respond.choice.getTimeStampInfoResp.info->buf, 1, res->respond.choice.getTimeStampInfoResp.info->size, fp);
			fclose(fp);
		}
		printf("gmt: %s\n", res->respTime.buf);
	}

	close(fd);

	return;
}
int main(int argc, char **argv)
{
	int *n = NULL;
	int ret = 0;
	int i=0;
	pthread_t tid[NUM_];

	if (argc > 1)
		g_type = atoi(argv[1]);
	for (i=0; i<NUM_; i++) {
		n = (int *)calloc(1, sizeof(int));
		*n = i;
		if (pthread_create(&tid[i], NULL, thread_fun, (void *)n) != 0) {
			printf("Can't create [thread %d]\n", i);
			return -1;
		}
		ret = pthread_detach(tid[i]);
	//	printf("i = %d, ret = %d\n", i, ret);
	}
	//sleep(100);
	pthread_exit(NULL);
	//exit(0);
}
