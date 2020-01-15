#ifndef __SIGN_VERIFY_SERVER__
#define __SIGN_VERIFY_SERVER__
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>

//#include <test_lib.h>
#ifndef SIGN_AND_VERIFY_SERVER
#define SIGN_AND_VERIFY_SERVER
#endif
#include <ldap.h>
#if 1
#include "lber.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
//#include <x509_int.h>
#endif
#include "util.h"
#include "SVSRequest.h"
#include "SVSRespond.h"
#include <macro.h>
#include <structure.h>
#include </root/zed/libevent-2.1.10-stable/event-internal.h>
#include <event2/event-config.h>
#include <event2/event_struct.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <sys/socket.h>
#include <base64.h>
#include <netinet/tcp.h>
#include "list.h"
#include "fm_def.h"
#include "fm_cpc_pub.h"
#include "EnvelopedData.h"
#include "SM2Cipher.h"
#include "SM2Signature.h"
#include "ContentInfo.h"
#include "SignedData.h"
#include "TimeStampReq.h"
#include "TimeStampResq.h"
#include "ESSCertID.h"
#include "SigningCertificate.h"
#include "ESSCertIDv2.h"
#include "SigningCertificateV2.h"

#undef _LOG_

#define _TIME_
#define _DEBUG_

#ifdef _DEBUG_
#define DEBUG(format, args...) printf("[%s][%s][%d] "format"", __FILE__, __func__, __LINE__, ##args)
#else
#define DEBUG(format, args...)
#endif
//#define Log(format, args...) fprintf(stderr, "[%s-%s][%s:%s:%d]: "format"", __DATE__, __TIME__, __FILE__, __func__, __LINE__, ##args)
#define NUM_OF_THREADS 6
#define MAX_FD_NUMBER_ONE_THREAD 1024

#define INTERVAL_CNT 2550000

struct queue {
	int data[MAX_FD_NUMBER_ONE_THREAD];
	int front, rear;
};
struct my_thread {
	pthread_t id;
	struct event_base *base;
	int fd[2];
	struct queue fd_queue;
	pthread_mutex_t lock;
};
struct ctl {
	int altNameLen;
	unsigned char *altName;
	int contentLen;
	unsigned char content[4096];
	struct list_head list;
};
#endif
