/*
  This example program provides a trivial server program that listens for TCP
  connections on port 9995.  When they arrive, it writes a short message to
  each client connection, and closes each connection once it is flushed.

  Where possible, it exits cleanly in response to a SIGINT (ctrl-c).
*/

#include "sign_verify_server.h"
#include <mysql.h>
#ifdef _TIME_
static float total_time, total_cnt;
static struct timeval g_tv_begin, g_tv_end;
//static struct timeval tv_begin, tv_end;
#endif
struct list_head CTL_list;
pthread_mutex_t g_ctl_lock__ = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t g_lock__ = PTHREAD_MUTEX_INITIALIZER;

//for debug_log write
pthread_mutex_t g_log_lock;  //for log write

static unsigned int g_thread_index; //work thread id (0 ~ NUM_OF_THREADS-1)

struct my_thread g_thread[NUM_OF_THREADS];

static const char empty[1]="";

static const char wake[] = " "; // one byte
//some OID 
static const int g_sm3_oid[] = {1, 2, 156, 10197, 1, 401};
static const int g_sha1_oid[] = {1, 3, 14, 3, 2, 26};
static const int g_data_oid[] = {1, 2, 156, 10197, 6, 1, 4, 2, 1};
static const int g_sign_oid[] = {1, 2, 156, 10197, 6, 1, 4, 2, 2};
static const int g_sm2_1_oid[] = {1, 2, 156, 10197, 1, 301, 1};
static const int g_signcertV2_oid[] = {1, 2, 840, 113549, 1, 9, 16, 2, 47};
static const int g_signcert_oid[] = {1, 2, 840, 113549, 1, 9, 16, 2, 12};
//for ldap

static char *ldap_type[] = {
	"svsSignCertPubkey",
	"svsSignCertSN"
};
static char *ctl_altNames[] = {
	"CA001",
	"CA002",
	"CA003",
	"CA004"
};
pthread_mutex_t g_ldap_lock;
static LDAP *g_ld = NULL;
static char g_username[1024]= "";
static char g_password[1024]= "";

static const int PORT = 9995;

static char g_dn[512]="";
static char g_sn[64]="";
static char g_appname[64]="";
static int  g_keyindex = 0xff;

static void listener_cb(struct evconnlistener *, evutil_socket_t,
    struct sockaddr *, int socklen, void *);

static int DEBUG_Log(const char *format, ...)
{
	time_t now = time(NULL);
	struct tm *cur_tm = localtime(&now);
	va_list list;

	va_start(list, format);
	pthread_mutex_lock(&g_log_lock);
	fprintf(stderr, "[%d-%02d-%02d %02d:%02d:%02d]: ", cur_tm->tm_year+1900, cur_tm->tm_mon+1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min,     cur_tm->tm_sec);
	vfprintf(stderr, format, list);
	pthread_mutex_unlock(&g_log_lock);
	va_end(list);

	return 0;
}
static int _init_cert_trust_list(void)
{
	int i = 0;
	struct ctl *tmp = NULL;
	INIT_LIST_HEAD(&CTL_list);
	for (i=0; i<sizeof(ctl_altNames)/sizeof(ctl_altNames[0]); i++) {
		tmp = (struct ctl*)calloc(1, sizeof(struct ctl));
		if (!tmp) {
			return 1;
		}
		tmp->altName = ctl_altNames[i];
		tmp->altNameLen = strlen(ctl_altNames[i]);
		tmp->contentLen = 0;
		my_list_add(&tmp->list, &CTL_list);
	}

	return 0;
}
#ifdef _TIME_
static void sig_usr(int signo)
{
	total_cnt = 0;
	total_time = 0;
}
#endif
static int _fm_sm3(const unsigned char *data, int data_len, unsigned char *hash, int *hash_len)
{
	int ret = SOR_OK;
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;

	/* Open Device */
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK)
	{ ret = SOR_UnknownErr; goto _end; }
	/* Hash Operation */
	f_ret = FM_CPC_SM3Init(f_hd, NULL, NULL, 0);
	DEBUG("FM_CPC_SM3Init f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	f_ret = FM_CPC_SM3Update(f_hd, data, data_len);
	DEBUG("FM_CPC_SM3Update f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	f_ret = FM_CPC_SM3Final(f_hd, hash, hash_len);
	DEBUG("FM_CPC_SM3Final f_ret = %08x| hash_len = %d\n", f_ret, *hash_len);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	/* Close Device */
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }

_end:
	return ret;
}
static int _fm_sha1(const unsigned char *data, int data_len, unsigned char *hash, int *hash_len)
{
	int ret = SOR_OK;
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;
	FM_U32	f_alg = FM_ALG_SHA1;

	/* Open Device */
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK)
	{ ret = SOR_UnknownErr; goto _end; }
	/* Hash Operation */
	f_ret = FM_CPC_HashInit(f_hd, f_alg);
	DEBUG("FM_CPC_HashInit f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	f_ret = FM_CPC_HashUpdate(f_hd, f_alg, data, data_len);
	DEBUG("FM_CPC_HashUpdate f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	f_ret = FM_CPC_HashFinal(f_hd, f_alg, hash, hash_len);
	DEBUG("FM_CPC_HashFinal f_ret = %08x| hash_len = %d\n", f_ret, *hash_len);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	/* Close Device */
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }

_end:
	return ret;
}
static void sig_int(int signo)
{
//	printf("[%s|%s|%d]:[Now the sign and verify server stops working!!!]\n", __FILE__, __func__, __LINE__);
	DEBUG_Log("[%s|%s|%d]:[Now the sign and verify server stops working!!!]\n", __FILE__, __func__, __LINE__);
	usleep(100000);
	exit(0);
}
static void der_encode_error_case(SVSRequest_t *req, char * buf, int * len)
{
	SVSRespond_t res;
	asn_enc_rval_t enc_ret;
	time_t now;
	struct tm *cur_tm;
	GeneralizedTime_t *tp = NULL;

	bzero(&res, sizeof(res));
	res.version = req->version;
	res.respType = req->reqType;
	res.respond.present = req->reqType+1;
	res.respond.choice.exportCertResp.respValue = GM_SYSTEM_FALURE;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s). The system must be wrong. You should check the server state\n", __FILE__, __func__, __LINE__, enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
}
static int get_len_from_tag(char *buf)
{
	int len = (unsigned char)buf[1];
	DEBUG("len = %02x\n", len);
	if (len <= 0x7F)
		return (len+2);
	else if (len == 0x81)
		return ((unsigned char)buf[2] + 3);
	else if (len == 0x82)
		return ((((unsigned char)buf[2])<<8)|((unsigned char)buf[3]))+4;
	else if (len == 0x83)
		return ((((unsigned char)buf[2])<<16)|(((unsigned char)buf[3])<<8)|((unsigned char)buf[4]))+5;

	return 0;
}
/* from '\xE0\xE1\xE2\xE3' to string
 */
static unsigned char *from_hex_to_string(const char *hex, int len)
{
	long long_len = len*3;
	int i = 0, j = 0;
	unsigned char *p = NULL;
	char hex_tmp[512] = "";
	for (i=2; i<len; i+=4) {
		DEBUG("hex[i] = %c, hex[i+1] = %c\n", hex[i], hex[i+1]);
		hex_tmp[j++] = hex[i];
		hex_tmp[j++] = hex[i+1];
		hex_tmp[j++] = ':';
		//ret += snprintf(hex_tmp+ret, long_len-ret, "%02X:", hex[i] & 0xff);
	}
	DEBUG("hex_tmp = %s, j = %d\n", hex_tmp, j);
	hex_tmp[--j] = '\0';
	DEBUG("hex_tmp = %s, long_len = %d\n", hex_tmp, long_len);
	p = string_to_hex(hex_tmp, &long_len);
	DEBUG("p = %s, long_len = %d\n", (char *)p, long_len);

	return p;
}
static void from_hexandstring_to_string(char *src, char *dst, int dst_len)
{
	int ret = 0;
	char *p=src, *p1=NULL, *p2=NULL, *p3=NULL;
	char on[256] = "";
	if (!src || !dst || dst_len<=0)
		return;
	*p++ = ' ';
	while (p && *p != '\0') {
		if (*p == '/')
			*p = ',';
		p++;
	}
	p = src+1;
	p1 = strstr(src, "O=");
	if (p1)
		p2 = strchr(p1, ',');
	memcpy(on, p1+2, p2-p1-2);
	DEBUG("on = %s, len = %d\n", on, p2-p1-2);
	p3 = from_hex_to_string(on, p2-p1-2);
	*(--p1) = '\0';
	DEBUG("p = %s, p2 = %s, p3 = %s\n", p, p2+1, p3);
	snprintf(dst, dst_len, "%s,O=%s%s", p, p3, p2);
	if (p3) {
		free(p3);
		p3 = NULL;
	}
}
int get_containerIndex_by_containerName(const char *name)
{
	int ret = -1;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	struct berval **vals = NULL;

	GetProfileString("./ldap.conf", "zed_sdn", sdn);
	DEBUG("sdn = %s\n", sdn);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsKeyContainerName");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				DEBUG("vals[0]->bv_len = %d\n", vals[0]->bv_len);
				if(!memcmp(name, vals[0]->bv_val, vals[0]->bv_len)) {
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsKeyContainerIndex");
					if (!vals) {
						DEBUG("attr found but no values\n");
					} else {
						ret = atoi(vals[0]->bv_val);
						DEBUG("ContainerIndex = %d\n", ret);
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}

	return ret;
}
#if 1
int get_index_by_certHash(int hash_method, const char *hash, int hash_len)
{
	int ret = -1;
	unsigned char sm3_hash[32];
	int sm3_hash_len = sizeof(sm3_hash);
	unsigned char sha1_hash[20];
	int sha1_hash_len = sizeof(sha1_hash);
	int flag = 0;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	struct berval **vals = NULL;

	GetProfileString("./ldap.conf", "zed_sdn", sdn);
	DEBUG("sdn = %s\n", sdn);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsSignCertificate;binary");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				DEBUG("vals[0]->bv_len = %d\n", vals[0]->bv_len);
				if (hash_method == SGD_SM3) {
					bzero(sm3_hash, sizeof(sm3_hash));
					sm3_hash_len = sizeof(sm3_hash);
					if (SOR_OK != _fm_sm3(vals[0]->bv_val, vals[0]->bv_len, sm3_hash, &sm3_hash_len)) {
						ldap_value_free( vals );
						vals = NULL;
						break;
					}
					if(sm3_hash_len==hash_len && !memcmp(hash, sm3_hash, sm3_hash_len)) {
						flag = 1;
					}
				} else if (hash_method == SGD_SHA1) {
					bzero(sha1_hash, sizeof(sha1_hash));
					sha1_hash_len = sizeof(sha1_hash);
					if (SOR_OK != _fm_sha1(vals[0]->bv_val, vals[0]->bv_len, sha1_hash, &sha1_hash_len)) {
						ldap_value_free( vals );
						vals = NULL;
						break;
					}
					if(sha1_hash_len==hash_len && !memcmp(hash, sha1_hash, sha1_hash_len)) {
						flag = 1;
					}
				} else {
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
				if(flag == 1) {
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsKeyContainerIndex");
					if (!vals) {
						DEBUG("attr found but no values\n");
					} else {
						ret = atoi(vals[0]->bv_val);
						DEBUG("ContainerIndex = %d\n", ret);
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}

	return ret;
}
#endif
static int mysql_parse_cert_by_index(int index, char *dn, char *sn, char *appname)
{
	LDAPMessage *result, *e;
	char sdn[128] = "";
	struct berval **vals = NULL;

	GetProfileString("./ldap.conf", "zed_sdn", sdn);
	DEBUG("sdn = %s\n", sdn);
//	pthread_mutex_lock(&g_ldap_lock);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsKeyContainerIndex");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				DEBUG("vals[0]->bv_len = %d\n", vals[0]->bv_len);
				if(atoi(vals[0]->bv_val) == index) {
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsSignCertDN");
					if (!vals) {
						DEBUG("attr found but no values\n");
					} else {
						memcpy(dn, vals[0]->bv_val, vals[0]->bv_len);
					}
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsSignCertSN");
					if (!vals) {
						DEBUG("attr found but no values\n");
					} else {
						memcpy(sn, vals[0]->bv_val, vals[0]->bv_len);
					}
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsAppName");
					if (!vals) {
						DEBUG("attr found but no values\n");
					} else {
						memcpy(appname, vals[0]->bv_val, vals[0]->bv_len);
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}
//	pthread_mutex_unlock(&g_ldap_lock);

	return 0;
}
static int mysql_parse_cert(char *buf, int len, char *dn, int dn_len, char *sn, int sn_len)
{
	int i, count;
	long val_long = 0;
	OCTET_STRING_t *tmp = NULL;
	struct x509_st *cert = NULL;
	ASN1_INTEGER *a = NULL;
	char dn_tmp[512] = "";

	if (!buf || len<=0) {
		DEBUG("cert is not valid!\n");
		return 1;
	}
	DEBUG("************\n");
	cert = d2i_X509(NULL, (const unsigned char **)&buf, len);
	if (cert == NULL) {
		DEBUG("cert is not x509 format!\n");
		return 1;
	}

	a = X509_get_serialNumber(cert);
	val_long = ASN1_INTEGER_get(a);
	snprintf(sn, sn_len, "%lx", val_long);

	X509_NAME_oneline(X509_get_subject_name(cert), dn_tmp, sizeof(dn_tmp));
	DEBUG("dn_tmp = %s\n", dn_tmp);
	from_hexandstring_to_string(dn_tmp, dn, dn_len);
	DEBUG("dn = %s\n", dn);

	X509_free(cert);
	return 0;
}
static int mysql_svs_interface_log_operate(int fd, char *appname, char *method, struct tm *cur_tm, char *dn, char *sn, int status, char *result1, char *result2)
{
	int ret = 0;
	int res = 0;
	char cmd[8192+4096];
	char log_data[4096];
	char base64_log_data[4096+4096];
	int base64_len = sizeof(base64_log_data);
	SignDataResp respond;
	MYSQL my_connection;
	struct sockaddr_in sa;
	int len = sizeof(sa);
	char str[INET_ADDRSTRLEN] = "";
	char *arg = "null", *remark = "null";
#if 0
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif

	if (!appname || *appname=='\0')
		appname = "未知应用";

	bzero(cmd, sizeof(cmd));
	bzero(log_data, sizeof(log_data));
	bzero(&respond, sizeof(respond));
	bzero(base64_log_data, sizeof(base64_log_data));
	DEBUG("*************\n");
	getpeername(fd, (struct sockaddr *)&sa, &len);
	DEBUG("*************\n");
	inet_ntop(AF_INET, &sa.sin_addr, str, sizeof(str)); 
	DEBUG("*************\n");
	if (*result1 != '\0') {
		snprintf(log_data, sizeof(log_data), "%s%s%s%s%s%s%s%s%d%4d-%02d-%02d%02d:%02d:%02d", appname, appname, arg, dn, str, method, remark, sn, status, cur_tm->tm_year+1900, cur_tm->tm_mon+1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
		DEBUG("log_data = %s\n", log_data);
		ret = base64_encode(base64_log_data, &base64_len, log_data, strlen(log_data));
		DEBUG("ret = %d, base64_len = %d\n", ret, base64_len);
		ret = Mid_SignDataInside(SGD_SM3_SM2, 0, "", base64_len, base64_log_data, &respond);
		DEBUG(" Mid_SignDataInside ret = %d\n", ret);
		snprintf(cmd, sizeof(cmd), "INSERT INTO svs_interface_log(appid, appname, dn, ip, method, optime, sn, status, result, signvalue) VALUES(\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%4d-%02d-%02d %02d:%02d:%02d\', \'%s\', %d, \'%s=%s\', \'%s\')", appname, appname, dn, str, method, cur_tm->tm_year+1900, cur_tm->tm_mon+1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec, sn, status, result1, result2, respond.signature);
	} else {
		snprintf(log_data, sizeof(log_data), "%s%s%s%s%s%s%s%s%d%4d-%02d-%02d%02d:%02d:%02d", appname, appname, arg, dn, str, method, remark, sn, status, cur_tm->tm_year+1900, cur_tm->tm_mon+1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec);
		DEBUG("log_data = %s\n", log_data);
		ret = base64_encode(base64_log_data, &base64_len, log_data, strlen(log_data));
		DEBUG("ret = %d, base64_len = %d\n", ret, base64_len);
		ret = Mid_SignDataInside(SGD_SM3_SM2, 0, "", base64_len, base64_log_data, &respond);
		DEBUG("Mid_SignDataInside ret = %d\n", ret);
		snprintf(cmd, sizeof(cmd), "INSERT INTO svs_interface_log(appid, appname, dn, ip, method, optime, sn, status, signvalue) VALUES(\'%s\', \'%s\', \'%s\', \'%s\', \'%s\', \'%4d-%02d-%02d %02d:%02d:%02d\', \'%s\', %d, \'%s\')", appname, appname, dn, str, method, cur_tm->tm_year+1900, cur_tm->tm_mon+1, cur_tm->tm_mday, cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec, sn, status, respond.signature);
	}
	DEBUG("cmd = %s\n", cmd);
	//DEBUG("log_data = %s\n", log_data);
	mysql_init(&my_connection);
	DEBUG("*************\n");
	if (mysql_real_connect(&my_connection, "192.168.1.137", "root", "111111", "svs", 0, NULL, 0)) {
		DEBUG("mysql_real_connect successfully\n");
		if (mysql_set_character_set(&my_connection, "utf8")) {
			 DEBUG_Log("[%s|%s|%d]:mysql_set_character_set Error\n", __FILE__, __func__, __LINE__);
			 return 0;
		} 
		res = mysql_query(&my_connection, cmd);
		DEBUG("mysql_query res = %d\n", res);
		mysql_close(&my_connection);
	} else {
		DEBUG_Log("[%s|%s|%d]:mysql_real_connect Error\n", __FILE__, __func__, __LINE__);
	}
#if 0
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return 0;
}
static int open_ldap(void)
{
	int ret;
	char host[1024] = "";
	int port=0;
	int version = LDAP_VERSION3;

	GetProfileString("./ldap.conf", "zed_host", host);
	GetProfileInt("./ldap.conf", "zed_port", &port);
	GetProfileString("./ldap.conf", "zed_username", g_username);
	GetProfileString("./ldap.conf", "zed_password", g_password);

	DEBUG("host = %s, port = %d, g_username = %s, g_password = %s\n", host, port, g_username, g_password);
	if (!(g_ld = ldap_open(host, port))) {
		DEBUG_Log("[%s|%s|%d]:ldap null\n", __FILE__, __func__, __LINE__);
		return 1;
	}
	DEBUG("********ldap open success*********\n");

	ret = ldap_set_option( g_ld, LDAP_OPT_PROTOCOL_VERSION, &version );
	DEBUG("ldap_set_option ret = %d\n", ret);
	if (ldap_simple_bind_s(g_ld, g_username, g_password) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_simple_bind_s Error\n", __FILE__, __func__, __LINE__);
		return 2;
	}
	DEBUG("********ldap_simple_bind_s success*********\n");

	return 0;
}
static int base64_encode_cert(Certificate_t *cert, unsigned char * base64cert, int * len)
{
	int ret = 0;
	asn_enc_rval_t enc_ret;
	unsigned char buff[4096] = "";
	int buff_len = sizeof(buff);

	enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, cert, buff, buff_len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
	if (enc_ret.encoded == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode asn_DEF_Certificate\n", __FILE__, __func__, __LINE__);
		ret = GM_SYSTEM_FALURE;
		return ret;
	}
	ret = base64_encode(base64cert, len, buff, enc_ret.encoded);
	DEBUG("ret = %d\n", ret);
	if (ret != 0) {
       	DEBUG_Log("[%s|%s|%d]:base64_encode error\n", __FILE__, __func__, __LINE__);
		ret = GM_SYSTEM_FALURE;
	}

	return ret;
}
static int get_bin_cert_by_index(char *buf, int *buf_len, int index)
{
	int ret = GM_ERROR_KEY_INDEX;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	struct berval **vals = NULL;

	GetProfileString("./ldap.conf", "zed_sdn", sdn);
	DEBUG("sdn = %s\n", sdn);
//	pthread_mutex_lock(&g_ldap_lock);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsKeyContainerIndex");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				DEBUG("vals[0]->bv_len = %d\n", vals[0]->bv_len);
				if(atoi(vals[0]->bv_val) == index) {
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsSignCertificate;binary");
					if (vals) {
						DEBUG("cert len = %d\n", vals[0]->bv_len);
						memcpy(buf, vals[0]->bv_val, vals[0]->bv_len);
						*buf_len = vals[0]->bv_len;
						ret = GM_SUCCESS;
					} else {
						DEBUG_Log("[%s|%s|%d]:attr found but no values\n", __FILE__, __func__, __LINE__);
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}
//	pthread_mutex_unlock(&g_ldap_lock);

	return ret;
}
static int get_pem_cert_by_index(char *buf, int buf_len, int index)
{
#ifdef _TIME_
	struct timeval tv_begin_2, tv_end_2;
	gettimeofday(&tv_begin_2, NULL);
#endif
	char start[] = "-----BEGIN CERTIFICATE-----\r\n";
	char end[] = "-----END CERTIFICATE-----\r\n";
	int ret = GM_ERROR_KEY_INDEX;
	int r = 0;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	struct berval **vals = NULL;
	int i = 0;

	int count = 0;
	char base64[2048] = "";
	int base64_len = sizeof(base64);

	GetProfileString("./ldap.conf", "zed_sdn", sdn);
	DEBUG("sdn = %s\n", sdn);
//	pthread_mutex_lock(&g_ldap_lock);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsKeyContainerIndex");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				DEBUG("vals[0]->bv_len = %d\n", vals[0]->bv_len);
				if(atoi(vals[0]->bv_val) == index) {
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsSignCertificate;binary");
					if (vals) {
						DEBUG("cert len = %d\n", vals[0]->bv_len);
						r = base64_encode(base64, &base64_len, vals[0]->bv_val, vals[0]->bv_len);
						DEBUG("base64_encode ret = %d\n", r);
						if (r) {
							ldap_value_free( vals );
							vals = NULL;
							break;
						}
						count += snprintf(buf+count, buf_len-count, "%s", start);
						while(base64_len > 64) {
							memcpy(buf+count, base64+i*64, 64);
							buf[strlen(buf)] = '\r';
							buf[strlen(buf)] = '\n';
							count += 66;
							base64_len -= 64;
							i++;
						}
						if (base64_len > 0) {
							memcpy(buf+count, base64+i*64, base64_len);
							buf[strlen(buf)] = '\r';
							buf[strlen(buf)] = '\n';
							count += base64_len + 2;
						}
						snprintf(buf+count, buf_len-count, "%s", end);
			//			printf("index = %d|cert = \n%s\n", index, buf);
						ret = GM_SUCCESS;
					} else {
						DEBUG_Log("[%s|%s|%d]:attr found but no values\n", __FILE__, __func__, __LINE__);
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}
//	pthread_mutex_unlock(&g_ldap_lock);

#ifdef _TIME_
	gettimeofday(&tv_end_2, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end_2.tv_sec-tv_begin_2.tv_sec+(tv_end_2.tv_usec-tv_begin_2.tv_usec)*0.000001);
#endif
	return ret;
}
static int get_keyindex_by_pubkey_or_certsn(const unsigned char *x, int type)
{
	int ret = 0xff;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	struct berval **vals = NULL;

	GetProfileString("./ldap.conf", "zed_sdn", sdn);
	DEBUG("sdn = %s\n", sdn);
//	pthread_mutex_lock(&g_ldap_lock);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, ldap_type[type]);
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				DEBUG("vals[0]->bv_len = %d\n", vals[0]->bv_len);
				if(!memcmp(x, vals[0]->bv_val, vals[0]->bv_len)) {
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsKeyContainerIndex");
					if (vals) {
						DEBUG("index len = %d, index val = %s\n", vals[0]->bv_len, vals[0]->bv_val);
						ret = atoi(vals[0]->bv_val);
					} else {
						DEBUG_Log("[%s|%s|%d]:attr found but no values\n", __FILE__, __func__, __LINE__);
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}
//	pthread_mutex_unlock(&g_ldap_lock);

	return ret;
}
static int get_signMethod(char *buf, int len)
{
	int ret = -1;
	struct x509_st *cert = NULL;
	EVP_PKEY *pk = NULL;

	if (!buf || len<=0) {
		DEBUG_Log("[%s|%s|%d]:cert is not valid!\n", __FILE__, __func__, __LINE__);
		return ret;
	}
	DEBUG("************\n");
	cert = d2i_X509(NULL, (const unsigned char **)&buf, len);
	if (cert == NULL) {
		DEBUG_Log("[%s|%s|%d]:cert is not x509 format!\n", __FILE__, __func__, __LINE__);
		return ret;
	} else {
		ret = SGD_SM3_SM2;
		pk = X509_get_pubkey(cert);
		if (pk && pk->type == EVP_PKEY_RSA)
			ret = SGD_SM3_RSA;
	}

	X509_free(cert);
	EVP_PKEY_free(pk);
	return ret;
}
static int get_ecc_pubkey_by_cert(char *buf, int len, FM_ECC_PublicKey *ecc_pk)
{
	int ret = GM_ERROR_CERT_DECODE;
	struct x509_st *cert = NULL;

	if (!buf || len<=0) {
		DEBUG_Log("[%s|%s|%d]:cert is not valid!\n", __FILE__, __func__, __LINE__);
		return ret;
	}
	DEBUG("************\n");
	cert = d2i_X509(NULL, (const unsigned char **)&buf, len);
	if (cert == NULL) {
		DEBUG_Log("[%s|%s|%d]:cert is not x509 format!\n", __FILE__, __func__, __LINE__);
		return ret;
	} else {
		ecc_pk->bits = 256;
		int i = 1;
		for (; i<cert->cert_info->key->public_key->length; i++) {
			printf("%02X ", cert->cert_info->key->public_key->data[i]);
		}
		printf("\n");
		memcpy(ecc_pk->x, cert->cert_info->key->public_key->data+1, 32);
		memcpy(ecc_pk->y, cert->cert_info->key->public_key->data+33, 32);
		ret = GM_SUCCESS;
	}

	X509_free(cert);
	return ret;
}
static OCTET_STRING_t *get_issuer_or_subject_from_cert(struct x509_st *cert, int flag, const char *type)
{
	char buffer[1024] = "";
	OCTET_STRING_t *tmp = NULL;
	char *p1=NULL, *p2=NULL;
	if (flag == 0) { //0 means issuer; non 0 means subject
		X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));
	} else {
		X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
	}
	if (p1 = strstr(buffer, type)) {
		p1 += strlen(type);
		if (p1) {
			if (p2 = strstr(p1, "/")) {
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, p1, p2-p1);
			} else {
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, p1, strlen(p1));
			}
		} else
			tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
	} else 
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));

	return tmp;
}
static OCTET_STRING_t *get_extensions_from_cert(struct x509_st *cert, const char *type)
{
	int num = 0;
	X509_EXTENSION *ex;
	ASN1_OBJECT *obj;
	const X509V3_EXT_METHOD *method = NULL;
	STACK_OF(CONF_VALUE) *val = NULL;
	void *ext_str = NULL;
	const unsigned char *p;
	CONF_VALUE *nval;
	char *value = NULL;
	int i = 0, j=0, found=0;

	char buf[128] = "";
	char buffer[2048] = "";
	OCTET_STRING_t *tmp = NULL;

	num = X509_get_ext_count(cert);

	for (i=0; i<num; i++)
	{
		ex = X509v3_get_ext(cert->cert_info->extensions, i);
		obj = X509_EXTENSION_get_object(ex);
		j = i2t_ASN1_OBJECT(buf, sizeof(buf), obj);
		if (strstr(buf, type)) {
			found = 1;
			DEBUG("*******\n");
			method = X509V3_EXT_get(ex);
			if (method) {
				DEBUG("*******\n");
				p = ex->value->data;
				if(method->it) 
					ext_str = ASN1_item_d2i(NULL, &p, ex->value->length, ASN1_ITEM_ptr(method->it));
				else 
					ext_str = method->d2i(NULL, &p, ex->value->length);

				if (!ext_str) {
					tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
					break;
				}
				if(method->i2s) {
					DEBUG("*******\n");
					value = method->i2s(method, ext_str);
					if (!value)
						tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
					else {
						tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, value, strlen(value));
						OPENSSL_free(value);
					}
					DEBUG("*******\n");
				} else if (method->i2v) {
					DEBUG("*******\n");
					val=method->i2v(method, ext_str, NULL);
					int k, count=0;
					DEBUG("*******\n");
					for(k = 0; k < sk_CONF_VALUE_num(val); k++) {
						nval = sk_CONF_VALUE_value(val, k);
						if (nval)
							count += snprintf(buffer+count, sizeof(buffer)-count, "%s:%s,", nval->name, nval->value);
						DEBUG("****k = %d|count = %d***\n", k, count);
					}
					tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)buffer, strlen(buffer)-1);
					sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
				} else if (method->i2r) {
					int save_fd = dup(STDOUT_FILENO);
					int fd = open(".CRL.txt", O_RDWR|O_CREAT|O_TRUNC, 0644);
					fflush(stdout);
					dup2(fd, STDOUT_FILENO);
					BIO *STDout=BIO_new_fp(stdout,BIO_NOCLOSE);
					method->i2r(method, ext_str, STDout, 12);
					fflush(stdout);
					dup2(save_fd,STDOUT_FILENO);
					close(fd);
					char *q = NULL;
					int r=0;
					FILE *fp = fopen(".CRL.txt", "r");
					if (fp) {
						while (fgets(buffer, sizeof(buffer), fp)) {
							if (q = strstr(buffer, "URI")) {
								break;
							}
						}
						fclose(fp);
					}
					if (*buffer == '\0')
						tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
					else {
						if (q)
							tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, q, strlen(q)-1);
						else
							tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer, strlen(buffer));
					}
				}
				if(method->it) ASN1_item_free(ext_str, ASN1_ITEM_ptr(method->it));
				else method->ext_free(ext_str);
			} else {
				DEBUG("method is null\n");
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
			}
			break;
		}
	}
					DEBUG("*******\n");
	if (!found)
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
					DEBUG("*******\n");

	return tmp;
}
static OCTET_STRING_t *get_extensions(struct x509_st *cert)
{
	int num = 0;
	X509_EXTENSION *ex;
	ASN1_OBJECT *obj;
	const X509V3_EXT_METHOD *method = NULL;
	STACK_OF(CONF_VALUE) *val = NULL;
	void *ext_str = NULL;
	const unsigned char *p;
	CONF_VALUE *nval;
	char *value = NULL;
	int i = 0, j=0;

	int count = 0;
	char buf[128] = "";
	char buffer[2048] = "";
	char buffer2[256] = "";
	OCTET_STRING_t *tmp = NULL;

	num = X509_get_ext_count(cert);

	for (i=0; i<num; i++)
	{
		ex = X509v3_get_ext(cert->cert_info->extensions, i);
		obj = X509_EXTENSION_get_object(ex);
		j = i2t_ASN1_OBJECT(buf, sizeof(buf), obj);
		count += snprintf(buffer+count, sizeof(buffer)-count, "%s:(", buf);
		DEBUG("*******\n");
		method = X509V3_EXT_get(ex);
		if (method) {
			DEBUG("*******\n");
			p = ex->value->data;
			if(method->it) 
				ext_str = ASN1_item_d2i(NULL, &p, ex->value->length, ASN1_ITEM_ptr(method->it));
			else 
				ext_str = method->d2i(NULL, &p, ex->value->length);

			if (!ext_str) {
				count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", "NULL");
				continue;
			}
			if(method->i2s) {
				DEBUG("*******\n");
				value = method->i2s(method, ext_str);
				if (!value)
					count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", "NULL");
				else {
					count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", value);
					OPENSSL_free(value);
					value = NULL;
				}
				DEBUG("*******\n");
			} else if (method->i2v) {
				DEBUG("*******\n");
				val=method->i2v(method, ext_str, NULL);
				int k;
				DEBUG("*******\n");
				for(k = 0; k < sk_CONF_VALUE_num(val); k++) {
					nval = sk_CONF_VALUE_value(val, k);
					if (nval)
						count += snprintf(buffer+count, sizeof(buffer)-count, "%s:%s,", nval->name, nval->value);
				}
				sk_CONF_VALUE_pop_free(nval, X509V3_conf_free);
				buffer[strlen(buffer)-1] = ')';
				buffer[strlen(buffer)] = '|';
				count++;
			} else if (method->i2r) {
				int save_fd = dup(STDOUT_FILENO);
				int fd = open(".CRL.txt", O_RDWR|O_CREAT|O_TRUNC, 0644);
				fflush(stdout);
				dup2(fd, STDOUT_FILENO);
				BIO *STDout=BIO_new_fp(stdout,BIO_NOCLOSE);
				method->i2r(method, ext_str, STDout, 12);
				fflush(stdout);
				dup2(save_fd,STDOUT_FILENO);
				close(fd);
				char *q = NULL;
				FILE *fp = fopen(".CRL.txt", "r");
				if (fp) {
					while (fgets(buffer2, sizeof(buffer2), fp)) {
						if (q = strstr(buffer2, "URI")) {
							break;
						}
					}
					fclose(fp);
				}
				if (*buffer2 == '\0')
					count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", "NULL");
				else {
					if (q)
						count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", q);
					else
						count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", buffer2);
				}
			}
			if(method->it) ASN1_item_free(ext_str, ASN1_ITEM_ptr(method->it));
			else method->ext_free(ext_str);
		} else {
			DEBUG("method is null\n");
			count += snprintf(buffer+count, sizeof(buffer)-count, "%s)|", "NULL");
		}
	}
	if (*buffer == '\0')
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));
	else
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)buffer, strlen(buffer)-1);
	DEBUG("count = %d\n", count);
	return tmp;
}
static OCTET_STRING_t * get_cert_details(char *buf, int len, int info_type)
{
	int ret = 0;
	long val_long = 0;
	OCTET_STRING_t *tmp = NULL;
	struct x509_st *cert = NULL, *cert_ex = NULL;
	EVP_PKEY *pk = NULL;
	unsigned char *q = NULL;
	char buffer[1024] = "";
	char buffer_tmp[1024] = "";
	int buffer_tmp_len = sizeof(buffer_tmp);
	unsigned char *tt = NULL;
	ASN1_INTEGER *a = NULL;
	ASN1_TIME *t = NULL;
	unsigned char base64_pubkey[128] = "";
	int base64_len = sizeof(base64_pubkey);

	if (!buf || len<=0) {
		DEBUG_Log("[%s|%s|%d]:cert is not valid!\n", __FILE__, __func__, __LINE__);
		return tmp;
	}
	DEBUG("************\n");
	cert = d2i_X509(NULL, (const unsigned char **)&buf, len);
	if (cert == NULL) {
		DEBUG_Log("[%s|%s|%d]:cert is not x509 format!\n", __FILE__, __func__, __LINE__);
		return tmp;
	} else {
		DEBUG("************\n");
		switch(info_type) {
			case SGD_CERT_VERSION:
				val_long = ASN1_INTEGER_get(cert->cert_info->version);
				DEBUG("val_long = %ld\n", val_long);
				snprintf(buffer, sizeof(buffer), "%ld", val_long);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer, strlen(buffer));
				break;
			case SGD_CERT_SERIAL:
				a = X509_get_serialNumber(cert);
				val_long = ASN1_INTEGER_get(a);
				snprintf(buffer, sizeof(buffer), "%lx", val_long);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer, strlen(buffer));
				break;
			case SGD_CERT_ISSUER:
				X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));
				from_hexandstring_to_string(buffer, buffer_tmp, buffer_tmp_len);
				//DEBUG("buffer_tmp = %s\n", buffer_tmp);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer_tmp, strlen(buffer_tmp));
				break;
			case SGD_CERT_VALID_TIME:
				snprintf(buffer, sizeof(buffer), "20%s|20%s", cert->cert_info->validity->notBefore->data, cert->cert_info->validity->notAfter->data);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)buffer, strlen(buffer));
				break;
			case SGD_CERT_SUBJECT:
				X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
				from_hexandstring_to_string(buffer, buffer_tmp, buffer_tmp_len);
				//printf("buffer_tmp = %s\n", buffer_tmp);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer_tmp, strlen(buffer_tmp));
				break;
			case SGD_CERT_DER_PUBLIC_KEY:
				ret = base64_encode(base64_pubkey, &base64_len, cert->cert_info->key->public_key->data+1, cert->cert_info->key->public_key->length-1);
				DEBUG("base64_encode ret = %d|base64_len = %d|base64_pubkey = %s\n", ret, base64_len, base64_pubkey);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)(base64_pubkey), base64_len);
				break;
			case SGD_CERT_DER_EXTENSIONS:
				tmp = get_extensions(cert);
				break;
			case SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO:
				tmp = get_extensions_from_cert(cert, "Authority Key Identifier");
				break;
			case SGD_EXT_SUBJECTKEYIDENTIFIER_INFO:
				tmp = get_extensions_from_cert(cert, "Subject Key Identifier");
				break;
			case SGD_EXT_KEYUSAGE_INFO:
				tmp = get_extensions_from_cert(cert, "Key Usage");
				break;
			case SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO:
				tmp = get_extensions_from_cert(cert, "Private Key Usage Period");
				break;
			case SGD_EXT_CERTIFICATEPOLICIES_INFO:
				tmp = get_extensions_from_cert(cert, "Certificate Policies");
				break;
			case SGD_EXT_POLICYMAPPINGS_INFO:
				tmp = get_extensions_from_cert(cert, "Policy Mappings");
				break;
			case SGD_EXT_POLICYCONSTRAINTS_INFO:
				tmp = get_extensions_from_cert(cert, "Policy Constraints");
				break;
			case SGD_EXT_EXTKEYUSAGE_INFO:
				tmp = get_extensions_from_cert(cert, "Extended Key Usage");
				break;
			case SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO:
				tmp = get_extensions_from_cert(cert, "CRL Distribution Points");
				break;
			case SGD_EXT_NETSCAPE_CERT_TYPE_INFO:
				tmp = get_extensions_from_cert(cert, "Netscape Certificate Extension");
				break;
			case SGD_EXT_SELFDEFINED_EXTENSION_INFO:
				tmp = get_extensions_from_cert(cert, "Self Defined");
				break;
			case SGD_EXT_BASICCONSTRAINTS_INFO:
				tmp = get_extensions_from_cert(cert, "Basic Constraints");
				break;
			case SGD_CERT_ISSUER_CN:
				tmp = get_issuer_or_subject_from_cert(cert, 0, "CN=");
				break;
			case SGD_CERT_ISSUER_O:
				tmp = get_issuer_or_subject_from_cert(cert, 0, "O=");
				DEBUG("tmp->buf = %s, tmp->size = %d\n", tmp->buf, tmp->size);
				memcpy(buffer_tmp, tmp->buf, tmp->size);
				OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
				tmp = NULL;
				tt = from_hex_to_string(buffer_tmp, strlen(buffer_tmp));
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (char *)tt, strlen(tt));
				if (tt) {
					free(tt);
					tt = NULL;
				}
				break;
			case SGD_CERT_ISSUER_OU:
				tmp = get_issuer_or_subject_from_cert(cert, 0, "OU=");
				break;
			case SGD_CERT_SUBJECT_CN:
				tmp = get_issuer_or_subject_from_cert(cert, 1, "CN=");
				break;
			case SGD_CERT_SUBJECT_O:
				tmp = get_issuer_or_subject_from_cert(cert, 1, "O=");
				DEBUG("tmp->buf = %s, tmp->size = %d\n", tmp->buf, tmp->size);
				memcpy(buffer_tmp, tmp->buf, tmp->size);
				OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
				tmp = NULL;
				tt = from_hex_to_string(buffer_tmp, strlen(buffer_tmp));
				DEBUG("tt = %s\n", tt);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (char *)tt, strlen(tt));
				if (tt) {
					free(tt);
					tt = NULL;
				}
				break;
			case SGD_CERT_SUBJECT_OU:
				tmp = get_issuer_or_subject_from_cert(cert, 1, "OU=");
				break;
			case SGD_CERT_SUBJECT_EMAIL:
				tmp = get_issuer_or_subject_from_cert(cert, 1, "emailAddress=");
				break;
			case SGD_CERT_NOTBEFORE_TIME:
				snprintf(buffer, sizeof(buffer), "20%s", cert->cert_info->validity->notBefore->data);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer, strlen(buffer));
				break;
			case SGD_CERT_NOTAFTER_TIME:
				snprintf(buffer, sizeof(buffer), "20%s", cert->cert_info->validity->notAfter->data);
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buffer, strlen(buffer));
				break;
			default:
				DEBUG("Not support x509 parse info type\n");
				DEBUG_Log("[%s|%s|%d]:Not support x509 parse info type\n", __FILE__, __func__, __LINE__);
				break;
		}
	}
	X509_free(cert);
	EVP_PKEY_free(pk);
	return tmp;
}
static OCTET_STRING_t * get_cert_info_by_oid(char *buf, int len, char *oid)
{
	int num = 0;
	X509_EXTENSION *ex;
	ASN1_OBJECT *obj;
	const unsigned char *p;
	char *value = NULL;
	int i = 0, j=0, k=0;
	struct x509_st *cert = NULL;

	char name[128] = "";
	char buffer[2048] = "";
	OCTET_STRING_t *tmp = NULL;

	if (!buf || len<=0) {
		DEBUG("cert is not valid!\n");
		return NULL;
	}
	DEBUG("************\n");
	cert = d2i_X509(NULL, (const unsigned char **)&buf, len);
	if (cert == NULL) {
		DEBUG("cert is not x509 format!\n");
		return NULL;
	}

	num = X509_get_ext_count(cert);

	for (i=0; i<num; i++)
	{
		ex = X509v3_get_ext(cert->cert_info->extensions, i);
		obj = X509_EXTENSION_get_object(ex);
		j = i2t_ASN1_OBJECT(name, sizeof(name), obj);
		DEBUG("name = %s\n", name);
		if (!memcmp(name, oid, strlen(name))) {
			DEBUG("*******ex->value->data = %s\n", ex->value->data);
			p = ex->value->data;
			for (k=0; k<ex->value->length; k++) {
				if (p[0] == 0x0c) {
					p++;
				} else {
					break;
				}
			}
			tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)p, ex->value->length-(p-ex->value->data));
			break;
		}
	}
	if (!tmp)
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, "NULL", strlen("NULL"));

	X509_free(cert);
	return tmp;
}
static void close_ldap(void)
{
	 ldap_unbind( g_ld );
}
static int set_fl(int fd, int flags)
{
	int val;
	if((val = fcntl(fd, F_GETFL, 0)) < 0)
		return -1;
	val = val|flags;
	if((val = fcntl(fd, F_SETFL, val)) < 0)
		return -1;
	return 0;
}
static int set_fd(int fd, int flags)
{
	int val;
	if((val = fcntl(fd, F_GETFD, 0)) < 0)
		return -1;
	val = val|flags;
	if((val = fcntl(fd, F_SETFD, val)) < 0)
		return -1;
	return 0;
}
static int init_queue(struct queue *q)
{
	q->front = 0;
	q->rear = 0;
	return 0;
}
static int size_queue(struct queue *q)
{
	return (q->rear - q->front + MAX_FD_NUMBER_ONE_THREAD)%MAX_FD_NUMBER_ONE_THREAD;
}
static int en_queue(struct queue *q, int fd)
{
	if ((q->rear+1)%MAX_FD_NUMBER_ONE_THREAD == q->front)
		return 1;
	q->data[q->rear] = fd;
	q->rear = (q->rear + 1)%MAX_FD_NUMBER_ONE_THREAD;
	return 0;
}
static int de_queue(struct queue *q, int *fd)
{
	if (q->rear == q->front)
		return 1;
	*fd = q->data[q->front];
	q->front = (q->front + 1)%MAX_FD_NUMBER_ONE_THREAD;
	return 0;
}
static int ExportCert_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_ERROR_CERT;
	SVSRespond_t res;
	asn_enc_rval_t enc_ret;
	asn_dec_rval_t dec_ret;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	char *a = NULL;
	struct berval **vals = NULL;
	int i = 0;
	Certificate_t *x = NULL;
	time_t now;
	struct tm *cur_tm;
	int r = 0;
	char base64[2048] = "";
	int base64_len = sizeof(base64);
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	DEBUG("request identification : %s\n", req->request.choice.exportCertReq.identification.buf);
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_exportCert;
	res.respond.present = Respond_PR_exportCertResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	ret = GetProfileString("./ldap.conf", "zed_sdn", sdn);
	if (ret != 0) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("sdn = %s\n", sdn);
//	pthread_mutex_lock(&g_ldap_lock);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
		ret = GM_SYSTEM_FALURE;
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsKeyContainerName");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				if (!memcmp(req->request.choice.exportCertReq.identification.buf, vals[0]->bv_val, vals[0]->bv_len)) {
					DEBUG("This is the container tha I'm looking for : svsKeyContainerName=%s\n", vals[0]->bv_val);
					ldap_value_free( vals );
					vals = NULL;
					vals = ldap_get_values_len(g_ld, e, "svsSignCertificate;binary");
					if (!vals) {
						DEBUG_Log("[%s|%s|%d]:attr found but no values\n", __FILE__, __func__, __LINE__);
					} else {
						DEBUG("vals[0]->len = %d, \n", vals[0]->bv_len );
						dec_ret = ber_decode(NULL, &asn_DEF_Certificate, (void **)&x, vals[0]->bv_val, vals[0]->bv_len);
						DEBUG("dec_ret.code = %d\n", dec_ret.code);
						if (dec_ret.code != RC_OK) {
							ret = GM_ERROR_CERT_DECODE;
							if (x) {
								free(x);
								x = NULL;
							}
						} else {
							ret = GM_SUCCESS;
						}
#ifdef _LOG_
						/* for mysql log */
						r = base64_encode(base64, &base64_len, vals[0]->bv_val, vals[0]->bv_len);
						DEBUG("base64_encode ret = %d\n", r);
						ldap_value_free( vals );
						vals = NULL;
						vals = ldap_get_values_len(g_ld, e, "svsSignCertDN");
						if (!vals) {
							DEBUG("attr found but no values\n");
						} else {
							memcpy(dn, vals[0]->bv_val, vals[0]->bv_len);
						}
						ldap_value_free( vals );
						vals = NULL;
						vals = ldap_get_values_len(g_ld, e, "svsSignCertSN");
						if (!vals) {
							DEBUG("attr found but no values\n");
						} else {
							memcpy(sn, vals[0]->bv_val, vals[0]->bv_len);
						}
						ldap_value_free( vals );
						vals = NULL;
						vals = ldap_get_values_len(g_ld, e, "svsAppName");
						if (!vals) {
							DEBUG("attr found but no values\n");
						} else {
							memcpy(appname, vals[0]->bv_val, vals[0]->bv_len);
						}
#endif
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}
//	pthread_mutex_unlock(&g_ldap_lock);
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "ExportCert", cur_tm, dn, sn, ret, "cert", base64);
#endif
	res.respond.choice.exportCertResp.cert = x;
	res.respond.choice.exportCertResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
	//	bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	if (x) {
		free(x);
		x = NULL;
	}
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
//	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int ParseCert_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	ParseCertResp respond;
	GeneralizedTime_t *tp = NULL;
	long version;
	asn_enc_rval_t enc_ret;
	OCTET_STRING_t *tmp = NULL;
	char buff[2048] = "";
	int buff_len = sizeof(buff);
	char dn[512]="", sn[64]="", appname[64]="";

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_parseCert;
	res.respond.present = Respond_PR_parseCertResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	DEBUG("*******&res.respTime = %p******\n", &res.respTime);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);
	DEBUG("req->request.choice.parseCertReq.infoType = %08x\n", req->request.choice.parseCertReq.infoType);
	bzero(&respond, sizeof(respond));
	enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, &req->request.choice.parseCertReq.cert, buff, buff_len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
	if (enc_ret.encoded == -1) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	} else {
		tmp = get_cert_details(buff, buff_len, req->request.choice.parseCertReq.infoType);
#ifdef _LOG_
		mysql_parse_cert(buff, buff_len, dn, sizeof(dn), sn, sizeof(sn));
		DEBUG("dn = %s, sn = %s\n", dn, sn);
#endif
	}
	if (!tmp) {
		DEBUG("tmp is null\n");
		ret = GM_ERROR_CERT_DECODE;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, empty, strlen(empty));
	}
	DEBUG("ret = %08x\n", ret);

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "ParseCert", cur_tm, dn, sn, ret, "info", tmp->buf);
#endif

	res.respond.choice.parseCertResp.respValue = ret;
	res.respond.choice.parseCertResp.info = tmp;

	DEBUG("*************\n");
	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	DEBUG("*************\n");
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int ValidateCert_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	ValidateCertResp respond;
	long state = 0;
	asn_enc_rval_t enc_ret;
	unsigned char base64cert[2048] = "";
	int buf_len = sizeof(base64cert);
	char buff[2048] = "";
	int buff_len = sizeof(buff);
	char dn[512]="", sn[64]="", appname[64]="", state_str[32]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_validateCert;
	res.respond.present = Respond_PR_validateCertResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	ret = base64_encode_cert(&req->request.choice.validateCertReq.cert, base64cert, &buf_len);
	if (ret) {
		DEBUG("base64_encode_cert Error ret = %d\n", ret);
	} else {
		bzero(&respond, sizeof(respond));
		ret = Mid_ValidateCert(base64cert, req->request.choice.validateCertReq.ocsp, &respond);
		DEBUG("Mid_ValidateCert ret = %08x\n", ret);
		if (!ret) {
			ret = respond.respValue;
			state = (long)respond.state;
		}
	}

	enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, &req->request.choice.validateCertReq.cert, buff, buff_len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
	if (enc_ret.encoded > 0) {
#ifdef _LOG_
		mysql_parse_cert(buff, buff_len, dn, sizeof(dn), sn, sizeof(sn));
		DEBUG("dn = %s, sn = %s\n", dn, sn);
#endif
	}
	snprintf(state_str, sizeof(state_str), "%d", state);
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "ValidateCert", cur_tm, dn, sn, ret, "state", state_str);
#endif

	DEBUG("ret = %d, state = %ld\n", ret, state);
	res.respond.choice.validateCertResp.respValue = ret;
	res.respond.choice.validateCertResp.state = &state;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignData_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignDataResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;
#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signData;
	res.respond.present = Respond_PR_signDataResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));
	DEBUG("req->request.choice.signDataReq.signMethod = %08x\n", req->request.choice.signDataReq.signMethod);
	DEBUG("req->request.choice.signDataReq.keyIndex = %d\n", req->request.choice.signDataReq.keyIndex);
	DEBUG("req->request.choice.signDataReq.keyValue.buf = %s\n", (char *)req->request.choice.signDataReq.keyValue.buf);
	DEBUG("req->request.choice.signDataReq.keyValue.size = %d\n", req->request.choice.signDataReq.keyValue.size);
	DEBUG("req->request.choice.signDataReq.inDataLen = %d\n", req->request.choice.signDataReq.inDataLen);
	//DEBUG("req->request.choice.signDataReq.inData.buf = %s\n", (char *)req->request.choice.signDataReq.inData.buf);
	in_base64_len = (req->request.choice.signDataReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.signDataReq.inData.buf, req->request.choice.signDataReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
//	printf("[%s:%d] base64_encode interval [%.6fs]\n", __func__, __LINE__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
	gettimeofday(&tv_begin, NULL);
#endif
//	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
	//printf("%08x|%d|%s|%d|%s\n", req->request.choice.signDataReq.signMethod, req->request.choice.signDataReq.keyIndex, req->request.choice.signDataReq.keyValue.buf, in_base64_len, in_base64);
	ret = Mid_SignData(req->request.choice.signDataReq.signMethod, req->request.choice.signDataReq.keyIndex, 
			req->request.choice.signDataReq.keyValue.buf, in_base64_len, in_base64, &respond);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("[%s:%d] Mid_SignData interval [%.6fs]\n", __func__, __LINE__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
	gettimeofday(&tv_begin, NULL);
#endif
	DEBUG("Mid_SignData ret = %08x\n", ret);
	if (!ret) {
		DEBUG("respond.signature = %s\n", respond.signature);
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignDataResp, respond.signature, strlen(respond.signature));
	}

_end:
#ifdef _LOG_
	mysql_parse_cert_by_index(req->request.choice.signDataReq.keyIndex, dn, sn, appname);
	DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
	mysql_svs_interface_log_operate(fd, appname, "SignData", cur_tm, dn, sn, ret, "signature", respond.signature);
#endif
	res.respond.choice.signDataResp.respValue = ret;
	res.respond.choice.signDataResp.signature = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("[%s:%d] interval [%.6fs]\n", __func__, __LINE__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedData_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int keyindex = 0xff;
	int ret = GM_SUCCESS;
	int signMethod = SGD_SM3_SM2;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	int respond = 0;
	asn_enc_rval_t enc_ret;
	unsigned char base64cert[2048] = "";
	int buf_len = sizeof(base64cert);
	char buff[2048] = "";
	int buff_len = sizeof(buff);
	char dn[512]="", sn[64]="", appname[64]="", state_str[32]="";
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedData;
	res.respond.present = Respond_PR_verifySignedDataResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	in_base64_len = (req->request.choice.verifySignedDataReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.verifySignedDataReq.inData.buf, req->request.choice.verifySignedDataReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);

	if (req->request.choice.verifySignedDataReq.type == 1) {
		ret = base64_encode_cert(req->request.choice.verifySignedDataReq.cert, base64cert, &buf_len);
		DEBUG("base64_encode_cert ret = %d\n", ret);
		if (ret) {
			ret = GM_SYSTEM_FALURE;
			goto _end;
		}
		enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, req->request.choice.verifySignedDataReq.cert, buff, buff_len);
		DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
		if (enc_ret.encoded == -1) {
       		DEBUG_Log("[%s|%s|%d]:Could not encode asn_DEF_Certificate\n", __FILE__, __func__, __LINE__);
			ret = GM_SYSTEM_FALURE;
			goto _end;
		}
#ifdef _LOG_
		mysql_parse_cert(buff, buff_len, dn, sizeof(dn), sn, sizeof(sn));
		DEBUG("dn = %s, sn = %s\n", dn, sn);
#endif
		signMethod = get_signMethod(buff, enc_ret.encoded);
	} else {
		keyindex = get_keyindex_by_pubkey_or_certsn(req->request.choice.verifySignedDataReq.certSN->buf, 1);
		DEBUG("get_keyindex_by_pubkey_or_certsn keyindex = %d\n", keyindex);
		if (keyindex == 0xff) {
			ret = GM_ERROR_CERT;
			goto _end;
		}
#ifdef _LOG_
		mysql_parse_cert_by_index(keyindex, dn, sn, appname);
		DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
#endif
		ret = get_bin_cert_by_index(buff, &buff_len, keyindex);
		DEBUG("get_bin_cert_by_index ret = %d\n", ret);
		if (ret) {
			ret = GM_ERROR_CERT;
			goto _end;
		}
		signMethod = get_signMethod(buff, buff_len);
	}
	DEBUG("signMethod = %08x\n", signMethod);
	DEBUG("req->request.choice.verifySignedDataReq.type = %d\n", req->request.choice.verifySignedDataReq.type);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("req->request.choice.verifySignedDataReq.inDataLen = %d\n", req->request.choice.verifySignedDataReq.inDataLen);
	DEBUG("req->request.choice.verifySignedDataReq.inData.buf = %s\n", (char *)req->request.choice.verifySignedDataReq.inData.buf);
	DEBUG("req->request.choice.verifySignedDataReq.verifyLevel = %d\n", req->request.choice.verifySignedDataReq.verifyLevel);

	ret = Mid_VerifySignedData(signMethod, req->request.choice.verifySignedDataReq.type, base64cert, keyindex, 
				in_base64_len, in_base64, 
				req->request.choice.verifySignedDataReq.signature.buf, req->request.choice.verifySignedDataReq.verifyLevel, &respond);
	DEBUG("Mid_VerifySignedData ret = %08x\n", ret);
	if (!ret) {
		ret = respond;
	}

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "VerifySignedData", cur_tm, dn, sn, ret, "", "");
#endif
	res.respond.choice.verifySignedDataResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
//	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignDataInit_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	int keyindex = 0xff;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignDataInitResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signDataInit;
	res.respond.present = Respond_PR_signDataInitResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));

	keyindex = get_keyindex_by_pubkey_or_certsn(req->request.choice.signDataInitReq.signerPublicKey->buf, 0);
//	DEBUG("req->request.choice.signDataInitReq.signerPublicKey = %s\n", req->request.choice.signDataInitReq.signerPublicKey->buf);
//	DEBUG("req->request.choice.signDataInitReq.signerPublicKey len = %d\n", req->request.choice.signDataInitReq.signerPublicKey->size);
	DEBUG("req->request.choice.signDataInitReq.signMethod = %08x\n", req->request.choice.signDataInitReq.signMethod);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("*(req->request.choice.signDataInitReq.signerIDLen) = %d\n", *(req->request.choice.signDataInitReq.signerIDLen));
	DEBUG("req->request.choice.signDataInitReq.signerID->buf = %s\n", req->request.choice.signDataInitReq.signerID->buf);
	DEBUG("req->request.choice.signDataInitReq.inDataLen = %d\n", req->request.choice.signDataInitReq.inDataLen);
	DEBUG("req->request.choice.signDataInitReq.inData.buf = %s\n", req->request.choice.signDataInitReq.inData.buf);
	in_base64_len = (req->request.choice.signDataInitReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.signDataInitReq.inData.buf, req->request.choice.signDataInitReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);

//			pthread_mutex_lock(&g_sign_data_lock);
	ret = Mid_SignDataInit(req->request.choice.signDataInitReq.signMethod, keyindex, *(req->request.choice.signDataInitReq.signerIDLen), 
			req->request.choice.signDataInitReq.signerID->buf, in_base64_len, in_base64, &respond);
	DEBUG("Mid_SignDataInit ret = %08x\n", ret);
	if (!ret) {
		ret = respond.respValue;
		DEBUG("respond.hashValue = %s\n", respond.hashValue);
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignDataInitResp, respond.hashValue, strlen(respond.hashValue));
	}

_end:
	bzero(g_dn, sizeof(g_dn));
	bzero(g_sn, sizeof(g_sn));
	bzero(g_appname, sizeof(g_appname));
#ifdef _LOG_
	mysql_parse_cert_by_index(keyindex, g_dn, g_sn, g_appname);
	DEBUG("g_dn = %s, g_sn = %s, g_appname = %s\n", g_dn, g_sn, g_appname);
	mysql_svs_interface_log_operate(fd, g_appname, "SignDataInit", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif

	res.respond.choice.signDataInitResp.respValue = ret;
	res.respond.choice.signDataInitResp.hashValue = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
//	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignDataUpdate_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignDataUpdateResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signDataUpdate;
	res.respond.present = Respond_PR_signDataUpdateResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));
	DEBUG("req->request.choice.signDataUpdateReq.signMethod = %08x\n", req->request.choice.signDataUpdateReq.signMethod);
	DEBUG("req->request.choice.signDataUpdateReq.hashValueLen = %d\n", req->request.choice.signDataUpdateReq.hashValueLen);
	DEBUG("req->request.choice.signDataUpdateReq.hashValue.buf = %s\n", req->request.choice.signDataUpdateReq.hashValue.buf);
	DEBUG("req->request.choice.signDataUpdateReq.inDataLen = %d\n", req->request.choice.signDataUpdateReq.inDataLen);
	DEBUG("req->request.choice.signDataUpdateReq.inData.buf = %s\n", req->request.choice.signDataUpdateReq.inData.buf);
	in_base64_len = (req->request.choice.signDataUpdateReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.signDataUpdateReq.inData.buf, req->request.choice.signDataUpdateReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);

	ret = Mid_SignDataUpdate(req->request.choice.signDataUpdateReq.signMethod, req->request.choice.signDataUpdateReq.hashValueLen, 
			req->request.choice.signDataUpdateReq.hashValue.buf, in_base64_len, in_base64, &respond);
	DEBUG("Mid_SignDataUpdate ret = %08x\n", ret);
	DEBUG("Mid_SignDataUpdate respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignDataUpdateResp, respond.hashValue, strlen(respond.hashValue));
	}

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "SignDataUpdate", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.signDataUpdateResp.respValue = ret;
	res.respond.choice.signDataUpdateResp.hashValue = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignDataFinal_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignDataFinalResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signDataFinal;
	res.respond.present = Respond_PR_signDataFinalResp;
	res.respond.choice.signDataFinalResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));
	DEBUG("req->request.choice.signDataFinalReq.signMethod = %08x\n", req->request.choice.signDataFinalReq.signMethod);
	DEBUG("req->request.choice.signDataFinalReq.keyIndex = %d\n", req->request.choice.signDataFinalReq.keyIndex);
	DEBUG("req->request.choice.signDataFinalReq.keyValue.buf = %s\n", req->request.choice.signDataFinalReq.keyValue.buf);
	DEBUG("req->request.choice.signDataFinalReq.hashValueLen = %d\n", req->request.choice.signDataFinalReq.hashValueLen);
	DEBUG("req->request.choice.signDataFinalReq.hashValue.buf = %s\n", req->request.choice.signDataFinalReq.hashValue.buf);
	ret = Mid_SignDataFinal(req->request.choice.signDataFinalReq.signMethod, req->request.choice.signDataFinalReq.keyIndex, 
			req->request.choice.signDataFinalReq.keyValue.buf, req->request.choice.signDataFinalReq.hashValueLen, 
			req->request.choice.signDataFinalReq.hashValue.buf, &respond);
//			pthread_mutex_unlock(&g_sign_data_lock);
	DEBUG("Mid_SignDataFinal ret = %08x\n", ret);
	DEBUG("respond.signaute = %s\n", respond.signaute);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignDataFinalResp, respond.signaute, strlen(respond.signaute));
	}

#ifdef _LOG_
	mysql_parse_cert_by_index(req->request.choice.signDataFinalReq.keyIndex, dn, sn, appname);
	DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
	mysql_svs_interface_log_operate(fd, appname, "SignDataFinal", cur_tm, dn, sn, ret, "signature", respond.signaute);
#endif
	res.respond.choice.signDataFinalResp.respValue = ret;
	res.respond.choice.signDataFinalResp.signature = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedDataInit_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	int keyindex = 0xff;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	VerifySignedDataInitResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedDataInit;
	res.respond.present = Respond_PR_verifySignedDataInitResp;
	res.respond.choice.verifySignedDataInitResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));

	keyindex = get_keyindex_by_pubkey_or_certsn(req->request.choice.verifySignedDataInitReq.signerPublicKey->buf, 0);
//	DEBUG("req->request.choice.verifySignedDataInitReq.signerPublicKey = %s\n", req->request.choice.verifySignedDataInitReq.signerPublicKey->buf);
	DEBUG("req->request.choice.verifySignedDataInitReq.signMethod = %08x\n", req->request.choice.verifySignedDataInitReq.signMethod);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("*(req->request.choice.verifySignedDataInitReq.signerIDLen) = %d\n", *(req->request.choice.verifySignedDataInitReq.signerIDLen));
	DEBUG("req->request.choice.verifySignedDataInitReq.signerID->buf = %s\n", req->request.choice.verifySignedDataInitReq.signerID->buf);
	DEBUG("req->request.choice.verifySignedDataInitReq.inDataLen = %d\n", req->request.choice.verifySignedDataInitReq.inDataLen);
	DEBUG("req->request.choice.verifySignedDataInitReq.inData.buf = %s\n", req->request.choice.verifySignedDataInitReq.inData.buf);
	in_base64_len = (req->request.choice.verifySignedDataInitReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.verifySignedDataInitReq.inData.buf, req->request.choice.verifySignedDataInitReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
//			pthread_mutex_lock(&g_verify_data_lock);
	ret = Mid_VerifySignedDataInit(req->request.choice.verifySignedDataInitReq.signMethod, keyindex, 
			*(req->request.choice.verifySignedDataInitReq.signerIDLen), req->request.choice.verifySignedDataInitReq.signerID->buf, in_base64_len, in_base64, &respond);
	DEBUG("Mid_VerifySignedDataInit ret = %08x\n", ret);
	DEBUG("Mid_VerifySignedDataInit respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_VerifySignedDataInitResp, respond.hashValue, strlen(respond.hashValue));
	}

_end:
	bzero(g_dn, sizeof(g_dn));
	bzero(g_sn, sizeof(g_sn));
	bzero(g_appname, sizeof(g_appname));
#ifdef _LOG_
	mysql_parse_cert_by_index(keyindex, g_dn, g_sn, g_appname);
	DEBUG("g_dn = %s, g_sn = %s, g_appname = %s\n", g_dn, g_sn, g_appname);
	mysql_svs_interface_log_operate(fd, g_appname, "verifySignedDataInit", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.verifySignedDataInitResp.respValue = ret;
	res.respond.choice.verifySignedDataInitResp.hashValue = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedDataUpdate_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	VerifySignDataUpdateResp respond;
	OCTET_STRING_t *tmp=NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedDataUpdate;
	res.respond.present = Respond_PR_verifySignedDataUpdateResp;
	res.respond.choice.verifySignedDataUpdateResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));
	DEBUG("req->request.choice.verifySignedDataUpdateReq.signMethod = %08x\n", req->request.choice.verifySignedDataUpdateReq.signMethod);
	DEBUG("req->request.choice.verifySignedDataUpdateReq.hashValueLen = %d\n", req->request.choice.verifySignedDataUpdateReq.hashValueLen);
	DEBUG("req->request.choice.verifySignedDataUpdateReq.hashValue.buf = %s\n", req->request.choice.verifySignedDataUpdateReq.hashValue.buf);
	DEBUG("req->request.choice.verifySignedDataUpdateReq.inDataLen = %d\n", req->request.choice.verifySignedDataUpdateReq.inDataLen);
	DEBUG("req->request.choice.verifySignedDataUpdateReq.inData.buf = %s\n", req->request.choice.verifySignedDataUpdateReq.inData.buf);
	in_base64_len = (req->request.choice.verifySignedDataUpdateReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.verifySignedDataUpdateReq.inData.buf, req->request.choice.verifySignedDataUpdateReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
	ret = Mid_VerifySignedDataUpdate(req->request.choice.verifySignedDataUpdateReq.signMethod, 
			req->request.choice.verifySignedDataUpdateReq.hashValueLen, req->request.choice.verifySignedDataUpdateReq.hashValue.buf, 
			in_base64_len, in_base64, &respond);
	DEBUG("Mid_VerifySignedDataUpdate ret = %08x\n", ret);
	DEBUG("Mid_VerifySignedDataUpdate respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_VerifySignedDataUpdateResp, respond.hashValue, strlen(respond.hashValue));
	}

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "verifySignedDataUpdate", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.verifySignedDataUpdateResp.respValue = ret;
	res.respond.choice.verifySignedDataUpdateResp.hashValue = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__,
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedDataFinal_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	int keyindex = 0xff;
	time_t now;
	struct tm *cur_tm;
	int respond = 0;
	asn_enc_rval_t enc_ret;
	unsigned char base64cert[2048] = "";
	int buf_len = sizeof(base64cert);
	char buff[2048] = "";
	int buff_len = sizeof(buff);
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedDataFinal;
	res.respond.present = Respond_PR_verifySignedDataFinalResp;
	res.respond.choice.verifySignedDataFinalResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	if (req->request.choice.verifySignedDataFinalReq.type == 1) {
		ret = base64_encode_cert(req->request.choice.verifySignedDataFinalReq.cert, base64cert, &buf_len);
		DEBUG("base64_encode_cert ret = %d\n", ret);
		if (ret) {
			ret = GM_SYSTEM_FALURE;
			goto _end;
		}
		enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, req->request.choice.verifySignedDataFinalReq.cert, buff, buff_len);
		DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
		if (enc_ret.encoded == -1) {
       		DEBUG_Log("[%s|%s|%d]:Could not encode asn_DEF_Certificate\n", __FILE__, __func__, __LINE__);
			ret = GM_SYSTEM_FALURE;
			goto _end;
		}
#ifdef _LOG_
		mysql_parse_cert(buff, buff_len, dn, sizeof(dn), sn, sizeof(sn));
		DEBUG("dn = %s, sn = %s\n", dn, sn);
#endif
	} else {
		keyindex = get_keyindex_by_pubkey_or_certsn(req->request.choice.verifySignedDataFinalReq.certSN->buf, 1);
		DEBUG("get_keyindex_by_pubkey_or_certsn keyindex = %d\n", keyindex);
		if (keyindex == 0xff) {
			ret = GM_ERROR_CERT;
			goto _end;
		}
#ifdef _LOG_
		mysql_parse_cert_by_index(keyindex, dn, sn, appname);
		DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
#endif
	}

	DEBUG("req->request.choice.verifySignedDataFinalReq.signMethod = %08x\n", req->request.choice.verifySignedDataFinalReq.signMethod);
	DEBUG("req->request.choice.verifySignedDataFinalReq.type = %d\n", req->request.choice.verifySignedDataFinalReq.type);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("req->request.choice.verifySignedDataFinalReq.hashValueLen = %d\n", req->request.choice.verifySignedDataFinalReq.hashValueLen);
	DEBUG("req->request.choice.verifySignedDataFinalReq.hashValue.buf = %s\n", req->request.choice.verifySignedDataFinalReq.hashValue.buf);
	DEBUG("req->request.choice.verifySignedDataFinalReq.signature.buf = %s\n", req->request.choice.verifySignedDataFinalReq.signature.buf);
	DEBUG("req->request.choice.verifySignedDataFinalReq.verifyLevel = %d\n", req->request.choice.verifySignedDataFinalReq.verifyLevel);
	ret = Mid_VerifySignedDataFinal(req->request.choice.verifySignedDataFinalReq.signMethod, req->request.choice.verifySignedDataFinalReq.type, 
		base64cert, keyindex, req->request.choice.verifySignedDataFinalReq.hashValueLen, 
		req->request.choice.verifySignedDataFinalReq.hashValue.buf, req->request.choice.verifySignedDataFinalReq.signature.buf, 
		req->request.choice.verifySignedDataFinalReq.verifyLevel, &respond);
//		pthread_mutex_unlock(&g_verify_data_lock);
	DEBUG("Mid_VerifySignedDataFinal ret = %08x, respond = %d\n", ret, respond);
	if (!ret) {
		ret = respond;
	}
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "verifySignedDataFinal", cur_tm, dn, sn, ret, "", "");
#endif
	res.respond.choice.verifySignedDataFinalResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	//printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignMessage_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignMessageResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	int buf_len = *len;
	char certinfo[4096] = "";
	int cert_len = sizeof(certinfo);
	char crl_path[128] = "sm2_person.crl";
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	DEBUG("*len = %d\n", *len);
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signMessage;
	res.respond.present = Respond_PR_signMessageResp;
	res.respond.choice.signMessageResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	in_base64_len = (req->request.choice.signMessageReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.signMessageReq.inData.buf, req->request.choice.signMessageReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
//	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
	bzero(&respond, sizeof(respond));
	DEBUG("req->request.choice.signMessageReq.signMethod = %08x\n", req->request.choice.signMessageReq.signMethod);
	DEBUG("req->request.choice.signMessageReq.keyIndex = %d\n", req->request.choice.signMessageReq.keyIndex);
	DEBUG("req->request.choice.signMessageReq.keyValue.buf = %s\n", req->request.choice.signMessageReq.keyValue.buf);
	DEBUG("req->request.choice.signMessageReq.inDataLen = %d\n", req->request.choice.signMessageReq.inDataLen);
//	DEBUG("req->request.choice.signMessageReq.inData.buf = %s\n", req->request.choice.signMessageReq.inData.buf);
	DEBUG("*(req->request.choice.signMessageReq.hashFlag) = %d\n", *(req->request.choice.signMessageReq.hashFlag));
	DEBUG("*(req->request.choice.signMessageReq.originalText) = %d\n", *(req->request.choice.signMessageReq.originalText));
	DEBUG("*(req->request.choice.signMessageReq.certificateChain) = %d\n", *(req->request.choice.signMessageReq.certificateChain));
	DEBUG("*(req->request.choice.signMessageReq.crl) = %d\n", *(req->request.choice.signMessageReq.crl));
	DEBUG("*(req->request.choice.signMessageReq.authenticationAttributes) = %d\n", *(req->request.choice.signMessageReq.authenticationAttributes));
	ret = get_pem_cert_by_index(certinfo, cert_len, req->request.choice.signMessageReq.keyIndex);
	DEBUG("get_pem_cert_by_index ret = %d\n", ret);
	if (ret)
		goto _end;
	ret = Mid_SignMessage(req->request.choice.signMessageReq.signMethod, req->request.choice.signMessageReq.keyIndex, 
			req->request.choice.signMessageReq.keyValue.buf, 
			in_base64_len, in_base64, certinfo, strlen(certinfo), 
			*(req->request.choice.signMessageReq.hashFlag), *(req->request.choice.signMessageReq.originalText), 
			*(req->request.choice.signMessageReq.certificateChain), crl_path, *(req->request.choice.signMessageReq.crl), 
			*(req->request.choice.signMessageReq.authenticationAttributes), &respond);
	DEBUG("Mid_SignMessage ret = %08x\n", ret);
	DEBUG("respond.signedMessage = %s|strlen(respond.signedMessage)=%d\n", respond.signedMessage, strlen(respond.signedMessage));
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignMessageResp, respond.signedMessage, strlen(respond.signedMessage));
	}

_end:
	g_keyindex = req->request.choice.signMessageReq.keyIndex;
#ifdef _LOG_
	mysql_parse_cert_by_index(req->request.choice.signMessageReq.keyIndex, dn, sn, appname);
	DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
	mysql_svs_interface_log_operate(fd, appname, "SignMessage", cur_tm, dn, sn, ret, "signedMessage", respond.signedMessage);
#endif

	res.respond.choice.signMessageResp.respValue = ret;
	res.respond.choice.signMessageResp.signedMessage = tmp;

	DEBUG("*len = %d, buf_len = %d\n", *len, buf_len);
	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, buf_len);
	DEBUG("*len = %d, buf_len = %d\n", *len, buf_len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
		DEBUG("*************\n");
   	}
	*len = enc_ret.encoded;
		DEBUG("*************\n");
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
		DEBUG("*************\n");
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif
		DEBUG("*************\n");

	return ret;
}
static int VerifySignedMessage_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	int signMethod = SGD_SM3_SM2;
	SVSRespond_t res;
	int keyindex = 0xff;
	time_t now;
	struct tm *cur_tm;
	int respond = 0;
	asn_enc_rval_t enc_ret;
	char certinfo[2048] = "";
	int cert_len = sizeof(certinfo);
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedMessage;
	res.respond.present = Respond_PR_verifySignedMessageResp;
	res.respond.choice.verifySignedMessageResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	in_base64_len = (req->request.choice.verifySignedMessageReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.verifySignedMessageReq.inData.buf, req->request.choice.verifySignedMessageReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
	DEBUG("signMethod = %08x\n", signMethod);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("req->request.choice.verifySignedMessageReq.inDataLen = %d\n", req->request.choice.verifySignedMessageReq.inDataLen);
	DEBUG("req->request.choice.verifySignedMessageReq.inData.buf = %s\n", req->request.choice.verifySignedMessageReq.inData.buf);
	DEBUG("req->request.choice.verifySignedMessageReq.signedMessage.buf = %s\n", req->request.choice.verifySignedMessageReq.signedMessage.buf);
	DEBUG("req->request.choice.verifySignedMessageReq.signedMessage.size = %d\n", req->request.choice.verifySignedMessageReq.signedMessage.size);
	DEBUG("*(req->request.choice.verifySignedMessageReq.hashFlag) = %d\n", *(req->request.choice.verifySignedMessageReq.hashFlag));
	DEBUG("*(req->request.choice.verifySignedMessageReq.originalText) = %d\n", *(req->request.choice.verifySignedMessageReq.originalText));
	DEBUG("*(req->request.choice.verifySignedMessageReq.certificateChain) = %d\n", *(req->request.choice.verifySignedMessageReq.certificateChain));
	DEBUG("*(req->request.choice.verifySignedMessageReq.crl) = %d\n", *(req->request.choice.verifySignedMessageReq.crl));
	DEBUG("*(req->request.choice.verifySignedMessageReq.authenticationAttributes) = %d\n", *(req->request.choice.verifySignedMessageReq.authenticationAttributes));
	ret = Mid_VerifySignedMessage(signMethod, keyindex, in_base64_len, 
			in_base64, req->request.choice.verifySignedMessageReq.signedMessage.buf, 
			*(req->request.choice.verifySignedMessageReq.hashFlag), *(req->request.choice.verifySignedMessageReq.originalText), 
			*(req->request.choice.verifySignedMessageReq.certificateChain), *(req->request.choice.verifySignedMessageReq.crl), 
			*(req->request.choice.verifySignedMessageReq.authenticationAttributes), &respond, certinfo, &cert_len);
	DEBUG("Mid_VerifySignedMessage ret = %08x, cert_len = %d\n", ret, cert_len);
	if (!ret) {
		ret = respond;
	}
_end:
#ifdef _LOG_
	mysql_parse_cert_by_index(g_keyindex, dn, sn, appname);
	DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
	mysql_svs_interface_log_operate(fd, appname, "VerifySignedMessage", cur_tm, dn, sn, ret, "", "");
#endif

	res.respond.choice.verifySignedMessageResp.respValue = ret;
	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignMessageInit_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	int keyindex = 0xff;
	time_t now;
	struct tm *cur_tm;
	SignMessageInitResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signMessageInit;
	res.respond.present = Respond_PR_signMessageInitResp;
	res.respond.choice.signMessageInitResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));

	keyindex = get_keyindex_by_pubkey_or_certsn(req->request.choice.signMessageInitReq.signerPublicKey->buf, 0);
	DEBUG("req->request.choice.signMessageInitReq.signMethod = %08x\n", req->request.choice.signMessageInitReq.signMethod);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("*(req->request.choice.signMessageInitReq.signerIDLen) = %d\n", *(req->request.choice.signMessageInitReq.signerIDLen));
	DEBUG("req->request.choice.signMessageInitReq.signerID->buf = %s\n", req->request.choice.signMessageInitReq.signerID->buf);
	DEBUG("req->request.choice.signMessageInitReq.inDataLen = %d\n", req->request.choice.signMessageInitReq.inDataLen);
	DEBUG("req->request.choice.signMessageInitReq.inData.buf = %s\n", req->request.choice.signMessageInitReq.inData.buf);
	in_base64_len = (req->request.choice.signMessageInitReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.signMessageInitReq.inData.buf, req->request.choice.signMessageInitReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
//			pthread_mutex_lock(&g_sign_message_lock);
	ret = Mid_SignMessageInit(req->request.choice.signMessageInitReq.signMethod, keyindex, *(req->request.choice.signMessageInitReq.signerIDLen),
			req->request.choice.signMessageInitReq.signerID->buf, in_base64_len, in_base64, &respond);
	DEBUG("Mid_SignMessageInit ret = %08x\n", ret);
	DEBUG("Mid_SignMessageInit respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignMessageInitResp, respond.hashValue, strlen(respond.hashValue));
	}

_end:
	bzero(g_dn, sizeof(g_dn));
	bzero(g_sn, sizeof(g_sn));
	bzero(g_appname, sizeof(g_appname));
#ifdef _LOG_
	mysql_parse_cert_by_index(keyindex, g_dn, g_sn, g_appname);
	DEBUG("g_dn = %s, g_sn = %s, g_appname = %s\n", g_dn, g_sn, g_appname);
	mysql_svs_interface_log_operate(fd, g_appname, "SignMessageInit", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.signMessageInitResp.respValue = ret;
	res.respond.choice.signMessageInitResp.hashValue = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignMessageUpdate_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignMessageUpdateResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signMessageUpdate;
	res.respond.present = Respond_PR_signMessageUpdateResp;
	res.respond.choice.signMessageUpdateResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));
	DEBUG("req->request.choice.signMessageUpdateReq.signMethod = %08x\n", req->request.choice.signMessageUpdateReq.signMethod);
	DEBUG("req->request.choice.signMessageUpdateReq.hashValueLen = %d\n", req->request.choice.signMessageUpdateReq.hashValueLen);
	DEBUG("req->request.choice.signMessageUpdateReq.hashValue.buf = %s\n", req->request.choice.signMessageUpdateReq.hashValue.buf);
	DEBUG("req->request.choice.signMessageUpdateReq.inDataLen = %d\n", req->request.choice.signMessageUpdateReq.inDataLen);
	DEBUG("req->request.choice.signMessageUpdateReq.inData.buf = %s\n", req->request.choice.signMessageUpdateReq.inData.buf);
	in_base64_len = (req->request.choice.signMessageUpdateReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.signMessageUpdateReq.inData.buf, req->request.choice.signMessageUpdateReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
	ret = Mid_SignMessageUpdate(req->request.choice.signMessageUpdateReq.signMethod, req->request.choice.signMessageUpdateReq.hashValueLen, 
			req->request.choice.signMessageUpdateReq.hashValue.buf, in_base64_len, in_base64, &respond);
	DEBUG("Mid_SignMessageUpdate ret = %08x\n", ret);
	DEBUG("Mid_SignMessageUpdate respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignMessageUpdateResp, respond.hashValue, strlen(respond.hashValue));
	}
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "SignMessageUpdate", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.signMessageUpdateResp.respValue = ret;
	res.respond.choice.signMessageUpdateResp.hashValue = tmp;
	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SignMessageFinal_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignMessageFinalResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
	unsigned char certinfo[2048] = "";
	int cert_len = sizeof(certinfo);
	char dn[512]="", sn[64]="", appname[64]="";
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_signMessageFinal;
	res.respond.present = Respond_PR_signMessageFinalResp;
	res.respond.choice.signMessageFinalResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));
	ret = get_pem_cert_by_index(certinfo, cert_len, req->request.choice.signMessageFinalReq.keyIndex);
	DEBUG("get_pem_cert_by_index ret = %d\n", ret);
	if (ret)
		goto _end;
	
	DEBUG("req->request.choice.signMessageFinalReq.signMethod = %08x\n", req->request.choice.signMessageFinalReq.signMethod);
	DEBUG("req->request.choice.signMessageFinalReq.keyIndex = %d\n", req->request.choice.signMessageFinalReq.keyIndex);
	DEBUG("req->request.choice.signMessageFinalReq.keyValue.buf = %s\n", req->request.choice.signMessageFinalReq.keyValue.buf);
	DEBUG("req->request.choice.signMessageFinalReq.hashValueLen = %d\n", req->request.choice.signMessageFinalReq.hashValueLen);
	DEBUG("req->request.choice.signMessageFinalReq.hashValue.buf = %s\n", req->request.choice.signMessageFinalReq.hashValue.buf);
	ret = Mid_SignMessageFinal(req->request.choice.signMessageFinalReq.signMethod, req->request.choice.signMessageFinalReq.keyIndex, 
			req->request.choice.signMessageFinalReq.keyValue.buf, certinfo, strlen(certinfo), req->request.choice.signMessageFinalReq.hashValueLen, 
			req->request.choice.signMessageFinalReq.hashValue.buf, &respond);
//			pthread_mutex_unlock(&g_sign_message_lock);
	DEBUG("Mid_SignMessageFinal ret = %08x\n", ret);
	DEBUG("Mid_SignMessageFinal respond.signedMessage = %s\n", respond.signedMessage);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_SignMessageFinalResp, respond.signedMessage, strlen(respond.signedMessage));
	}
_end:
#ifdef _LOG_
	mysql_parse_cert_by_index(req->request.choice.signMessageFinalReq.keyIndex, dn, sn, appname);
	DEBUG("dn = %s, sn = %s, appname = %s\n", dn, sn, appname);
	mysql_svs_interface_log_operate(fd, appname, "SignMessageFinal", cur_tm, dn, sn, ret, "signedMessage", respond.signedMessage);
#endif
	res.respond.choice.signMessageFinalResp.respValue = ret;
	res.respond.choice.signMessageFinalResp.signedMessage = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedMessageInit_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	int keyindex = 0xff;
	time_t now;
	struct tm *cur_tm;
	VerifySignedMessageInitResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
//	char certinfo[2048] = "";
//	int cert_len = sizeof(certinfo);
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedMessageInit;
	res.respond.present = Respond_PR_verifySignedMessageInitResp;
	res.respond.choice.verifySignedMessageInitResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	bzero(&respond, sizeof(respond));

	keyindex = get_keyindex_by_pubkey_or_certsn(req->request.choice.verifySignedMessageInitReq.signerPublicKey->buf, 0);
	DEBUG("req->request.choice.verifySignedMessageInitReq.signMethod = %08x\n", req->request.choice.verifySignedMessageInitReq.signMethod);
	DEBUG("req->request.choice.verifySignedMessageInitReq.signerPublicKey = %s\n", req->request.choice.verifySignedMessageInitReq.signerPublicKey->buf);
	DEBUG("keyindex = %d\n", keyindex);
	DEBUG("*(req->request.choice.verifySignedMessageInitReq.signerIDLen) = %d\n", *(req->request.choice.verifySignedMessageInitReq.signerIDLen));
	DEBUG("req->request.choice.verifySignedMessageInitReq.signerID->buf = %s\n", req->request.choice.verifySignedMessageInitReq.signerID->buf);
	DEBUG("req->request.choice.verifySignedMessageInitReq.inDataLen = %d\n", req->request.choice.verifySignedMessageInitReq.inDataLen);
	DEBUG("req->request.choice.verifySignedMessageInitReq.inData.buf = %s\n", req->request.choice.verifySignedMessageInitReq.inData.buf);
	in_base64_len = (req->request.choice.verifySignedMessageInitReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.verifySignedMessageInitReq.inData.buf, req->request.choice.verifySignedMessageInitReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
//			pthread_mutex_lock(&g_verify_message_lock);
	ret = Mid_VerifySignedMessageInit(req->request.choice.verifySignedMessageInitReq.signMethod, keyindex, 
			*(req->request.choice.verifySignedMessageInitReq.signerIDLen), req->request.choice.verifySignedMessageInitReq.signerID->buf, 
			in_base64_len, in_base64, &respond);
	DEBUG("Mid_VerifySignedMessageInit ret = %08x\n", ret);
	DEBUG("Mid_VerifySignedMessageInit respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_VerifySignedMessageInitResp, respond.hashValue, strlen(respond.hashValue));
	}

_end:
	bzero(g_dn, sizeof(g_dn));
	bzero(g_sn, sizeof(g_sn));
	bzero(g_appname, sizeof(g_appname));
#ifdef _LOG_
	mysql_parse_cert_by_index(keyindex, g_dn, g_sn, g_appname);
	DEBUG("g_dn = %s, g_sn = %s, g_appname = %s\n", g_dn, g_sn, g_appname);
	mysql_svs_interface_log_operate(fd, g_appname, "verifySignedMessageInit", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.verifySignedMessageInitResp.respValue = ret;
	res.respond.choice.verifySignedMessageInitResp.hashValue = tmp;
	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedMessageUpdate_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	SignMessageUpdateResp respond;
	OCTET_STRING_t *tmp = NULL;
	asn_enc_rval_t enc_ret;
//	char certinfo[2048] = "";
//	int cert_len = sizeof(certinfo);
	unsigned char *in_base64 = NULL;
	int in_base64_len = 0;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedMessageUpdate;
	res.respond.present = Respond_PR_verifySignedMessageUpdateResp;
	res.respond.choice.verifySignedMessageUpdateResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.verifySignedMessageUpdateReq.signMethod = %08x\n", req->request.choice.verifySignedMessageUpdateReq.signMethod);
	DEBUG("req->request.choice.verifySignedMessageUpdateReq.hashValueLen = %d\n", req->request.choice.verifySignedMessageUpdateReq.hashValueLen);
	DEBUG("req->request.choice.verifySignedMessageUpdateReq.hashValue.buf = %s\n", req->request.choice.verifySignedMessageUpdateReq.hashValue.buf);
	DEBUG("req->request.choice.verifySignedMessageUpdateReq.inDataLen = %d\n", req->request.choice.verifySignedMessageUpdateReq.inDataLen);
	DEBUG("req->request.choice.verifySignedMessageUpdateReq.inData.buf = %s\n", req->request.choice.verifySignedMessageUpdateReq.inData.buf);
	in_base64_len = (req->request.choice.verifySignedMessageUpdateReq.inDataLen*1.5)+4;
	DEBUG("in_base64_len = %d\n", in_base64_len);
	in_base64 = (unsigned char *)calloc(1, in_base64_len);
	if (!in_base64) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	ret = base64_encode(in_base64, &in_base64_len, req->request.choice.verifySignedMessageUpdateReq.inData.buf, req->request.choice.verifySignedMessageUpdateReq.inDataLen);
	DEBUG("base64_encode ret = %d\n", ret);
	if (ret) {
		ret = GM_SYSTEM_FALURE;
		goto _end;
	}
	DEBUG("in_base64 = %s, in_base64_len = %d\n", in_base64, in_base64_len);
	ret = Mid_VerifySignedMessageUpdate(req->request.choice.verifySignedMessageUpdateReq.signMethod, 
			req->request.choice.verifySignedMessageUpdateReq.hashValueLen, req->request.choice.verifySignedMessageUpdateReq.hashValue.buf, 
			in_base64_len, in_base64, &respond);
	DEBUG("Mid_VerifySignedMessageUpdate ret = %08x\n", ret);
	DEBUG("Mid_VerifySignedMessageUpdate respond.hashValue = %s\n", respond.hashValue);
	if (!ret) {
		ret = respond.respValue;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_VerifySignedMessageUpdateResp, respond.hashValue, strlen(respond.hashValue));
	}
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "verifySignedMessageUpdate", cur_tm, g_dn, g_sn, ret, "hashValue", respond.hashValue);
#endif
	res.respond.choice.verifySignedMessageUpdateResp.respValue = ret;
	res.respond.choice.verifySignedMessageUpdateResp.hashValue = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	if (in_base64) {
		free(in_base64);
		in_base64 = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifySignedMessageFinal_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	int respond = 0;
	asn_enc_rval_t enc_ret;
	char dn[512]="", sn[64]="", appname[64]="";
//	char certinfo[2048] = "";
	//int cert_len = sizeof(certinfo);
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifySignedMessageFinal;
	res.respond.present = Respond_PR_verifySignedMessageFinalResp;
	res.respond.choice.verifySignedMessageFinalResp.respValue = ret;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.verifySignedMessageFinalReq.signMethod = %08x\n", req->request.choice.verifySignedMessageFinalReq.signMethod);
	DEBUG("req->request.choice.verifySignedMessageFinalReq.hashValueLen = %d\n", req->request.choice.verifySignedMessageFinalReq.hashValueLen);
	DEBUG("req->request.choice.verifySignedMessageFinalReq.hashValue.buf = %s\n", req->request.choice.verifySignedMessageFinalReq.hashValue.buf);
	DEBUG("req->request.choice.verifySignedMessageFinalReq.signature.buf = %s\n", req->request.choice.verifySignedMessageFinalReq.signature.buf);
	ret = Mid_VerifySignedMessageFinal(req->request.choice.verifySignedMessageFinalReq.signMethod, 
			req->request.choice.verifySignedMessageFinalReq.hashValueLen, req->request.choice.verifySignedMessageFinalReq.hashValue.buf, 
			req->request.choice.verifySignedMessageFinalReq.signature.buf, false, false, true, false, false, &respond);
	DEBUG("Mid_VerifySignedMessageFinal ret = %08x\n", ret);
//			pthread_mutex_unlock(&g_verify_message_lock);
	if (!ret) {
		ret = respond;
	}

#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "verifySignedMessageFinal", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	res.respond.choice.verifySignedMessageFinalResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int SetCertTrustList_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_CTLNOTFOUND;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	struct ctl *pos = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_setCertTrustList;
	res.respond.present = Respond_PR_setCertTrustListResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.setCertTrustListReq.ctlAltName.buf = %s\n", req->request.choice.setCertTrustListReq.ctlAltName.buf);
	DEBUG("req->request.choice.setCertTrustListReq.ctlContent.buf = %s\n", req->request.choice.setCertTrustListReq.ctlContent.buf);
	DEBUG("req->request.choice.setCertTrustListReq.ctlContentLen = %d\n", req->request.choice.setCertTrustListReq.ctlContentLen);
	pthread_mutex_lock(&g_ctl_lock__);
	list_for_each_entry(pos, &CTL_list, list) {
		if (!memcmp(req->request.choice.setCertTrustListReq.ctlAltName.buf, pos->altName, req->request.choice.setCertTrustListReq.ctlAltName.size)) {
	DEBUG("*******************\n");
#if 1
	DEBUG("*******************\n");
			memcpy(pos->content, req->request.choice.setCertTrustListReq.ctlContent.buf, req->request.choice.setCertTrustListReq.ctlContentLen);
			DEBUG("pos->content = %s\n", pos->content);
			pos->contentLen = req->request.choice.setCertTrustListReq.ctlContentLen;
#endif
			ret = SOR_OK;
			break;
		}
	}
	pthread_mutex_unlock(&g_ctl_lock__);

#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "setCertTrustList", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("SetCertTrustList_handle ret = %08x\n", ret);
	res.respond.choice.setCertTrustListResp.respValue = ret;
	DEBUG("*******************\n");

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("*******************\n");
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	DEBUG("*******************\n");
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int GetCertTrustListAltNames_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_OK;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	char *p = NULL;
	int cnt = 0;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	struct ctl *pos = NULL;
	OCTET_STRING_t *tmp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_getCertTrustListAltNames;
	res.respond.present = Respond_PR_getCertTrustListAltNamesResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	pthread_mutex_lock(&g_ctl_lock__);
	list_for_each_entry(pos, &CTL_list, list) {
		cnt += (pos->altNameLen+1);
	}
	DEBUG("cnt = %d\n", cnt);
	p = (char *)calloc(1, cnt);
	if (!p) {
		ret = SOR_MemoryErr;
	} else {
		cnt = 0;
		list_for_each_entry(pos, &CTL_list, list) {
			memcpy(p+cnt, pos->altName, pos->altNameLen);
			cnt+=pos->altNameLen;
			p[cnt] = '@';
			cnt++;
		}
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)p, cnt-1);
		free(p);
	}
	pthread_mutex_unlock(&g_ctl_lock__);

#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "getCertTrustListAltNames", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("GetCertTrustListAltNames_handle ret = %08x\n", ret);
	res.respond.choice.getCertTrustListAltNamesResp.respValue = ret;
	res.respond.choice.getCertTrustListAltNamesResp.ctlAltNames = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int GetCertTrustList_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_CTLNOTFOUND;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	struct ctl *pos = NULL;
	OCTET_STRING_t *tmp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_getCertTrustList;
	res.respond.present = Respond_PR_getCertTrustListResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.getCertTrustListReq.ctlAltName.buf = %s\n", req->request.choice.getCertTrustListReq.ctlAltName.buf);
	pthread_mutex_lock(&g_ctl_lock__);
	list_for_each_entry(pos, &CTL_list, list) {
		if (!memcmp(req->request.choice.getCertTrustListReq.ctlAltName.buf, pos->altName, req->request.choice.getCertTrustListReq.ctlAltName.size)) {
			tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)pos->content, pos->contentLen);
			ret = SOR_OK;
			break;
		}
	}
	pthread_mutex_unlock(&g_ctl_lock__);

#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "getCertTrustList", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("GetCertTrustList_handle ret = %08x\n", ret);
	res.respond.choice.getCertTrustListResp.respValue = ret;
	res.respond.choice.getCertTrustListResp.ctlContent = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int DelCertTrustList_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_CTLNOTFOUND;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	struct ctl *pos = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_delCertTrustList;
	res.respond.present = Respond_PR_delCertTrustListResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.delCertTrustListReq.ctlAltName.buf = %s\n", req->request.choice.delCertTrustListReq.ctlAltName.buf);
	pthread_mutex_lock(&g_ctl_lock__);
	list_for_each_entry(pos, &CTL_list, list) {
		if (!memcmp(req->request.choice.delCertTrustListReq.ctlAltName.buf, pos->altName, req->request.choice.delCertTrustListReq.ctlAltName.size)) {
			pos->contentLen = 0;
			ret = SOR_OK;
			break;
		}
	}
	pthread_mutex_unlock(&g_ctl_lock__);

#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "delCertTrustList", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("DelCertTrustList_handle ret = %08x\n", ret);
	res.respond.choice.delCertTrustListResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int InitCertAppPolicy_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_OK;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_initCertAppPolicy;
	res.respond.present = Respond_PR_initCertAppPolicyResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.initCertAppPolicyReq.policyName.buf = %s\n", req->request.choice.initCertAppPolicyReq.policyName.buf);

#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "initCertAppPolicy", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("InitCertAppPolicy_handle ret = %08x\n", ret);
	res.respond.choice.initCertAppPolicyResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int GetServerCertificate_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_UnknownErr;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	LDAPMessage *result, *e;
	char sdn[128] = "";
	char *a = NULL;
	struct berval **vals = NULL;
	unsigned char * in_base64 = NULL;
	int in_base64_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_getServerCertificate;
	res.respond.present = Respond_PR_getServerCertificateResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.getServerCertificateReq.containerName = %s\n", req->request.choice.getServerCertificateReq.containerName.buf);
	DEBUG("req->request.choice.getServerCertificateReq.certUsage = %d\n", req->request.choice.getServerCertificateReq.certUsage);
	if (req->request.choice.getServerCertificateReq.certUsage != 1 && req->request.choice.getServerCertificateReq.certUsage != 2) {
		ret = SOR_PARAMETERNOTSUPPORTErr;
		goto _end;
	}

	ret = GetProfileString("./ldap.conf", "zed_sdn", sdn);
	if (ret != 0) {
		ret = SOR_UnknownErr;
		goto _end;
	}
	DEBUG("sdn = %s\n", sdn);
//	pthread_mutex_lock(&g_ldap_lock);
	if (ldap_search_s(g_ld, sdn, LDAP_SCOPE_SUBTREE, "(objectClass=*)", NULL, 0, &result) != LDAP_SUCCESS) {
		DEBUG_Log("[%s|%s|%d]:ldap_search_s Error\n", __FILE__, __func__, __LINE__);
		ret = SOR_UnknownErr;
	} else {
		DEBUG("********ldap_search_s success*********\n");
		for (e=ldap_first_entry(g_ld,result); e!=NULL; e=ldap_next_entry(g_ld,e)) {

			vals = ldap_get_values_len(g_ld, e, "svsKeyContainerName");
			if (!vals) {
				DEBUG("no values, continue\n");
			} else {
				if (!memcmp(req->request.choice.getServerCertificateReq.containerName.buf, vals[0]->bv_val, vals[0]->bv_len)) {
					DEBUG("This is the container tha I'm looking for : svsKeyContainerName=%s\n", vals[0]->bv_val);
					ldap_value_free( vals );
					vals = NULL;
					if (req->request.choice.getServerCertificateReq.certUsage == 1) {
						DEBUG("***************\n");
						vals = ldap_get_values_len(g_ld, e, "svsExchangeCertificate;binary");
					}else {
						DEBUG("***************\n");
						vals = ldap_get_values_len(g_ld, e, "svsSignCertificate;binary");
					}
					if (!vals) {
						DEBUG_Log("[%s|%s|%d]:attr found but no values\n", __FILE__, __func__, __LINE__);
					} else {
						DEBUG("vals[0]->len = %d, \n", vals[0]->bv_len );
#ifdef _DEBUG____
						FILE *fp;
						fp = fopen("cert.cer", "wb");
						fwrite(vals[0]->bv_val, 1, vals[0]->bv_len, fp);
						fclose(fp);
#endif
						in_base64_len = (vals[0]->bv_len * 1.5)+4;
						DEBUG("in_base64_len = %d\n", in_base64_len);
						in_base64 = (unsigned char *)calloc(1, in_base64_len);
						if (!in_base64) {
							ret = SOR_MemoryErr;
						} else {
							ret = base64_encode(in_base64, &in_base64_len, vals[0]->bv_val, vals[0]->bv_len);
							DEBUG("base64_encode ret = %d, in_base64_len = %d\n", ret, in_base64_len);
							if (ret) {
								ret = SOR_UnknownErr;
							} else {
								tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)in_base64, in_base64_len);
								ret = SOR_OK;
							}
							ldap_value_free( vals );
							vals = NULL;
						}
#ifdef _LOG_
						/* for mysql log */
						vals = ldap_get_values_len(g_ld, e, "svsSignCertDN");
						if (!vals) {
							DEBUG("attr found but no values\n");
						} else {
							memcpy(dn, vals[0]->bv_val, vals[0]->bv_len);
						}
						ldap_value_free( vals );
						vals = NULL;
						vals = ldap_get_values_len(g_ld, e, "svsSignCertSN");
						if (!vals) {
							DEBUG("attr found but no values\n");
						} else {
							memcpy(sn, vals[0]->bv_val, vals[0]->bv_len);
						}
						ldap_value_free( vals );
						vals = NULL;
						vals = ldap_get_values_len(g_ld, e, "svsAppName");
						if (!vals) {
							DEBUG("attr found but no values\n");
						} else {
							memcpy(appname, vals[0]->bv_val, vals[0]->bv_len);
						}
#endif
					}
					ldap_value_free( vals );
					vals = NULL;
					break;
				}
			}
			ldap_value_free( vals );
			vals = NULL;
		}
		ldap_msgfree( result );
	}

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "getServerCertificate", cur_tm, dn, sn, ret, "cert", in_base64);
#endif
	DEBUG("GetServerCertificate_handle ret = %08x\n", ret);
	res.respond.choice.getServerCertificateResp.respValue = ret;
	res.respond.choice.getServerCertificateResp.cert = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	if (in_base64) {
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int GenRandom_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_OK;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	unsigned char *random = NULL;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_genRandom;
	res.respond.present = Respond_PR_genRandomResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.genRandomReq.randomLen = %d\n", req->request.choice.genRandomReq.randomLen);
	random = (unsigned char *)calloc(1, req->request.choice.genRandomReq.randomLen);
	if (!random) {
		ret = SOR_GenRandErr;
		goto _end;
	}
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) goto _end;
	f_ret = FM_CPC_GenRandom(f_hd, req->request.choice.genRandomReq.randomLen, random);
	DEBUG("FM_CPC_GenRandom f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) {
		FM_CPC_CloseDevice(f_hd);
		ret = SOR_GenRandErr;
		goto _end;
	} else {
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char *)random, req->request.choice.genRandomReq.randomLen);
	}
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "genRandom", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("GenRandom_handle ret = %08x\n", ret);
	res.respond.choice.genRandomResp.respValue = ret;
	res.respond.choice.genRandomResp.random = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	if (random) {
		free(random);
		random = NULL;
	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int GetCertInfoByOid_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_UnknownErr;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	unsigned char *in_data = NULL;
	int in_data_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_getCertInfoByOid;
	res.respond.present = Respond_PR_getCertInfoByOidResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.getCertInfoByOidReq.base64EncodeCert = %s\n", req->request.choice.getCertInfoByOidReq.base64EncodeCert.buf);
	DEBUG("req->request.choice.getCertInfoByOidReq.oid = %s\n", req->request.choice.getCertInfoByOidReq.oid.buf);
	in_data = (unsigned char *)calloc(1, req->request.choice.getCertInfoByOidReq.base64EncodeCert.size);
	if (!in_data) {
		ret = SOR_MemoryErr;
		goto _end;
	}
	in_data_len = req->request.choice.getCertInfoByOidReq.base64EncodeCert.size;
	ret = base64_decode(in_data, &in_data_len, req->request.choice.getCertInfoByOidReq.base64EncodeCert.buf, req->request.choice.getCertInfoByOidReq.base64EncodeCert.size);
	DEBUG("base64_decode ret = %d\n", ret);
	if (ret) {
		ret = SOR_UnknownErr;
		goto _end;
	}
#ifdef _LOG_
	if (mysql_parse_cert(in_data, in_data_len, dn, sizeof(dn), sn, sizeof(sn))) {
		DEBUG("mysql_parse_cert ERROR\n");
		ret = SOR_CERTINVALIDErr;
		goto _end;
	}
	DEBUG("dn = %s, sn = %s, info = %s\n", dn, sn, tmp?tmp->buf:"");
#endif
	tmp = get_cert_info_by_oid(in_data, in_data_len, req->request.choice.getCertInfoByOidReq.oid.buf);

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, appname, "getCertInfoByOid", cur_tm, dn, sn, ret, "info", tmp?tmp->buf:"");
#endif
	DEBUG("GetCertInfoByOid_handle ret = %08x\n", ret);
	res.respond.choice.getCertInfoByOidResp.respValue = ret;
	res.respond.choice.getCertInfoByOidResp.info = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	if (in_data) {
		free(in_data);
		in_data = NULL;
	}
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
#define SYM_OID_SIZE 7
#define ECC_OID_SIZE 7
#define ENVE_OID_SIZE 9
static int EncryptData_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_UnknownErr;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	unsigned char *in_data = NULL;
	int in_data_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";
	FM_ECC_PublicKey	f_sm2pubkey;
	Certificate_t *x = NULL;
	asn_dec_rval_t dec_ret;
	unsigned char *buff = NULL;
	int buff_len = 0;
	unsigned char *out_data = NULL;
	int out_data_len = 0;
	int sym_oid[SYM_OID_SIZE] = {1, 2, 156, 10197, 1};
	int ecc_oid[ECC_OID_SIZE] = {1, 2, 156, 10197, 1, 301, 3}; //default SM2_3 1.2.156.10197.1.301.3
	int enve_oid[] = {1, 2, 156, 10197, 6, 1, 4, 2, 3}; //envelopedData
	EnvelopedData_t enve;
	RecipientInfo_t recip;
	
	//fm card var
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;
	//symmetric algorithm
	FM_U32	f_len = 16;
	FM_U32	f_key = FM_HKEY_BYDEV_TEMP;
	FM_U8	f_symkey[16] = "", f_iv[16] = "";
	FM_U8	*f_cipher = NULL;
	FM_U32	f_cipherlen = 0;
	FM_U32	f_alg = FM_ALG_SM4;
	FM_U32	f_mode = FM_ALGMODE_CBC;
	//ecc algorithm
	FM_U32	f_sm2alg = FM_ALG_SM2_3;
	FM_HKEY	f_sm2key = FM_HKEY_FROM_HOST;
	FM_ECC_Cipher	f_sm2cipher;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_encryptData;
	res.respond.present = Respond_PR_encryptDataResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.encryptDataReq.cert = %s\n", req->request.choice.encryptDataReq.cert.buf);
	DEBUG("req->request.choice.encryptDataReq.symMethod = %08x\n", req->request.choice.encryptDataReq.symMethod);
	DEBUG("req->request.choice.encryptDataReq.indata = %s|%d\n", req->request.choice.encryptDataReq.inData.buf, req->request.choice.encryptDataReq.inData.size);

	switch(req->request.choice.encryptDataReq.symMethod) {
		case SGD_SM1_ECB:
			sym_oid[5]=102; sym_oid[6]=1; f_alg = FM_ALG_SM1; f_mode = FM_ALGMODE_ECB;
			break;
		case SGD_SM1_CBC:
			sym_oid[5]=102; sym_oid[6]=2; f_alg = FM_ALG_SM1; f_mode = FM_ALGMODE_CBC;
			break;
		case SGD_SM1_CFB:
			sym_oid[5]=102; sym_oid[6]=4; f_alg = FM_ALG_SM1; f_mode = FM_ALGMODE_CFB;
			break;
		case SGD_SM1_OFB:
			sym_oid[5]=102; sym_oid[6]=3; f_alg = FM_ALG_SM1; f_mode = FM_ALGMODE_OFB;
			break;
		case SGD_SM1_MAC:
			sym_oid[5]=102; sym_oid[6]=7; f_alg = FM_ALG_SM1; f_mode = FM_ALGMODE_MAC;
			break;
		case SGD_SSF33_ECB:
			sym_oid[5]=103; sym_oid[6]=1; f_alg = FM_ALG_SSF33; f_mode = FM_ALGMODE_ECB;
			break;
		case SGD_SSF33_CBC:
			sym_oid[5]=103; sym_oid[6]=2; f_alg = FM_ALG_SSF33; f_mode = FM_ALGMODE_CBC;
			break;
		case SGD_SSF33_CFB:
			sym_oid[5]=103; sym_oid[6]=4; f_alg = FM_ALG_SSF33; f_mode = FM_ALGMODE_CFB;
			break;
		case SGD_SSF33_OFB:
			sym_oid[5]=103; sym_oid[6]=3; f_alg = FM_ALG_SSF33; f_mode = FM_ALGMODE_OFB;
			break;
		case SGD_SSF33_MAC:
			sym_oid[5]=103; sym_oid[6]=7; f_alg = FM_ALG_SSF33; f_mode = FM_ALGMODE_MAC;
			break;
		case SGD_SM4_ECB:
			sym_oid[5]=104; sym_oid[6]=1; f_alg = FM_ALG_SM4; f_mode = FM_ALGMODE_ECB;
			break;
		case SGD_SM4_CBC:
			sym_oid[5]=104; sym_oid[6]=2; f_alg = FM_ALG_SM4; f_mode = FM_ALGMODE_CBC;
			break;
		case SGD_SM4_CFB:
			sym_oid[5]=104; sym_oid[6]=4; f_alg = FM_ALG_SM4; f_mode = FM_ALGMODE_CFB;
			break;
		case SGD_SM4_OFB:
			sym_oid[5]=104; sym_oid[6]=3; f_alg = FM_ALG_SM4; f_mode = FM_ALGMODE_OFB;
			break;
		case SGD_SM4_MAC:
			sym_oid[5]=104; sym_oid[6]=7;f_alg = FM_ALG_SM4; f_mode = FM_ALGMODE_MAC;
			break;
		default:
			DEBUG("Not suport symMethod\n");
			ret = SOR_PARAMETERNOTSUPPORTErr;
			goto _end;
	}

	in_data = (unsigned char *)calloc(1, req->request.choice.encryptDataReq.cert.size);
	if (!in_data) { ret = SOR_MemoryErr; goto _end;	}
	in_data_len = req->request.choice.encryptDataReq.cert.size;
	ret = base64_decode(in_data, &in_data_len, req->request.choice.encryptDataReq.cert.buf, req->request.choice.encryptDataReq.cert.size);
	DEBUG("base64_decode ret = %d, in_data_len = %d\n", ret, in_data_len);
	if (ret) { ret = SOR_UnknownErr; goto _end; }

	ret = get_ecc_pubkey_by_cert(in_data, in_data_len, &f_sm2pubkey);
	DEBUG("get_ecc_pubkey_by_cert ret = %08X\n", ret);
	if (ret) goto _end;
	if (mysql_parse_cert(in_data, in_data_len, dn, sizeof(dn), sn, sizeof(sn))) {
		DEBUG("mysql_parse_cert ERROR\n");
		ret = SOR_CERTINVALIDErr;
		goto _end;
	}
	dec_ret = ber_decode(NULL, &asn_DEF_Certificate, (void **)&x, in_data, in_data_len);
	DEBUG("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code != RC_OK) { ret = SOR_CERTINVALIDErr; goto _end; }

	ret = SOR_UnknownErr;
	bzero(&f_sm2cipher, sizeof(f_sm2cipher));
	bzero(&enve, sizeof(enve));
	enve.version = 0;

	f_cipherlen = req->request.choice.encryptDataReq.inData.size+16;
	f_cipher = (FM_U8 *)calloc(1, f_cipherlen);
	if (!f_cipher) { ret = SOR_MemoryErr; goto _end; }

	buff_len = req->request.choice.encryptDataReq.inData.size+400;
	buff = (unsigned char *)calloc(1, buff_len);
	if (!buff) { ret = SOR_MemoryErr; goto _end; }

	/* Open Device */
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) goto _end;
	f_ret = FM_CPC_GenKey(f_hd, f_alg, f_len, &f_key, f_symkey);
	DEBUG("FM_CPC_GenKey f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) {
		goto _close;
	} else {
		/*	symmetric encryption	*/
		f_ret = FM_CPC_Encrypt(f_hd, f_key, f_alg, f_mode, req->request.choice.encryptDataReq.inData.buf, req->request.choice.encryptDataReq.inData.size, f_cipher, &f_cipherlen, f_symkey, sizeof(f_symkey), f_iv, sizeof(f_iv));
		DEBUG("FM_CPC_Encrypt f_ret = %08x, f_cipherlen = %d\n", f_ret, f_cipherlen);
		if (f_ret != FME_OK) { ret = SOR_ENCRYPTDATAErr; goto _delkey; }
		/*	ECC encryption	*/
		f_ret = FM_CPC_ECCEncrypt(f_hd, f_sm2alg, f_sm2key, f_symkey, sizeof(f_symkey), &f_sm2pubkey, &f_sm2cipher);
		DEBUG("FM_CPC_ECCEncrypt f_ret = %08x\n", f_ret);
		if (f_ret != FME_OK) goto _delkey;
		ret = OBJECT_IDENTIFIER_set_arcs(&enve.encryptedContentInfo.contentType, enve_oid, sizeof(enve_oid[0]), sizeof(enve_oid)/sizeof(enve_oid[0]));
		DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
		if (ret) { ret = SOR_UnknownErr; goto _delkey; }
		ret = OBJECT_IDENTIFIER_set_arcs(&enve.encryptedContentInfo.contentEncryptionAlgorithmIdentifier.algorithm, sym_oid, sizeof(sym_oid[0]), sizeof(sym_oid)/sizeof(sym_oid[0]));
		DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
		if (ret) { ret = SOR_UnknownErr; goto _delkey; }
		enve.encryptedContentInfo.encryptedContent = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, f_cipher, f_cipherlen);
		
		bzero(&recip, sizeof(recip));
		recip.version = 0;
		memcpy(&recip.issuerAndSerialNumber.issuer, &x->tbsCertificate.issuer, sizeof(Name_t));
		DEBUG("sn = %s|%ld\n", sn, atol(sn));
		recip.issuerAndSerialNumber.serialNumber = atol(sn);
		ret = OBJECT_IDENTIFIER_set_arcs(&recip.keyEncryptionAlgorithm.algorithm, ecc_oid, sizeof(ecc_oid[0]), sizeof(ecc_oid)/sizeof(ecc_oid[0]));
		DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
		if (ret) { ret = SOR_UnknownErr; goto _delkey; }
		ret = OCTET_STRING_fromBuf(&recip.encryptedKey, (const char*)&f_sm2cipher, sizeof(f_sm2cipher));
		DEBUG("OCTET_STRING_fromBuf ret = %d\n", ret);
		if (ret) { ret = SOR_UnknownErr; goto _delkey; }
		ret = asn_set_add(&enve.recipientInfos.list, &recip);
		DEBUG("asn_set_add ret = %d\n", ret);
		DEBUG("enve.recipientInfos.list.count = %d, enve.recipientInfos.list.size = %d\n", enve.recipientInfos.list.count, enve.recipientInfos.list.size);
		if (ret) { ret = SOR_UnknownErr; goto _delkey; }
		enc_ret = der_encode_to_buffer(&asn_DEF_EnvelopedData, &enve, buff, buff_len);
		DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
		if (enc_ret.encoded == -1) { ret = SOR_UnknownErr; goto _delkey; }

		out_data_len = (int)(enc_ret.encoded*1.5)+4;
		out_data = (unsigned char *)calloc(1, out_data_len);
		if (!out_data) { ret = SOR_MemoryErr; goto _end; }
		ret = base64_encode(out_data, &out_data_len, buff, enc_ret.encoded);
		DEBUG("base64_encode ret = %d, out_data_len = %d\n", ret, out_data_len);
		if (ret) { ret = SOR_UnknownErr; goto _delkey; }
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, out_data, out_data_len);
		ret = SOR_OK;
	}
_delkey:
	f_ret = FM_CPC_DelKey(f_hd, f_key);
_close:
	/* Close Device*/
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "encryptData", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("EncryptData_handle ret = %08x\n", ret);
	res.respond.choice.encryptDataResp.respValue = ret;
	res.respond.choice.encryptDataResp.outData = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	DEBUG("*******in_data = %p********\n", in_data);
	if (in_data) {
		free(in_data);
		in_data = NULL;
	}
	DEBUG("*******f_cipher = %p********\n", f_cipher);
	if (f_cipher) {
		free(f_cipher);
		f_cipher = NULL;
	}
	DEBUG("*******x = %p********\n", x);
	if (x) {
		free(x);
		x = NULL;
	}
	DEBUG("*******buff = %p********\n", buff);
	if (buff) {
		free(buff);
		buff = NULL;
	}
	if (out_data) {
		free(out_data);
		out_data = NULL;
	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, &recip.encryptedKey, 1);
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int DecryptData_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_UnknownErr;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	asn_dec_rval_t dec_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	unsigned char *in_data = NULL;
	int in_data_len = 0;
	int containerIndex = 0;
	EnvelopedData_t	*enve = NULL;

	int sym_oid[SYM_OID_SIZE] = {0};
	int sym_oid_size = SYM_OID_SIZE;
	int ecc_oid[ECC_OID_SIZE] = {0};
	int ecc_oid_size = ECC_OID_SIZE;
	int enve_oid[ENVE_OID_SIZE] = {0};
	int enve_oid_size = ENVE_OID_SIZE;

	//fm card var
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;
	//symmetric algorithm
	FM_U32	f_len = 16;
	FM_U32	f_key = FM_HKEY_FROM_HOST;
	FM_U8	f_iv[16] = "";
	FM_U32	f_alg = FM_ALG_SM4;
	FM_U32	f_mode = FM_ALGMODE_CBC;
	//ecc algorithm
	FM_U32	f_sm2alg = FM_ALG_SM2_3;
	FM_HKEY	f_sm2key = 0;
	FM_ECC_Cipher	f_sm2cipher;
	FM_U8	f_sm2out[32] = "";
	FM_U32	f_sm2outlen = sizeof(f_sm2out);
#ifdef _DEBUG_
	FM_ECC_PrivateKey	f_sm2prikey;
#endif

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_decryptData;
	res.respond.present = Respond_PR_decryptDataResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.decryptDataReq.containerName = %s\n", req->request.choice.decryptDataReq.containerName.buf);
	DEBUG("req->request.choice.decryptDataReq.indata = %s\n", req->request.choice.decryptDataReq.inData.buf);

	containerIndex = get_containerIndex_by_containerName(req->request.choice.decryptDataReq.containerName.buf);
	DEBUG("containerIndex = %d\n", containerIndex);
	if (containerIndex < 0) { ret = SOR_KeyNotFountErr; goto _end; }
	f_sm2key = (FM_HKEY)(FM_UP)(containerIndex+128);

	in_data = (unsigned char *)calloc(1, req->request.choice.decryptDataReq.inData.size);
	if (!in_data) { ret = SOR_MemoryErr; goto _end; }
	in_data_len = req->request.choice.decryptDataReq.inData.size;
	ret = base64_decode(in_data, &in_data_len, req->request.choice.decryptDataReq.inData.buf, req->request.choice.decryptDataReq.inData.size);
	DEBUG("base64_decode ret = %d\n", ret);
	if (ret) { ret = SOR_UnknownErr; goto _end; }

	dec_ret = ber_decode(NULL, &asn_DEF_EnvelopedData, (void **)&enve, in_data, in_data_len);
	DEBUG("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code != RC_OK) { ret = SOR_IndataErr; goto _end; }
	DEBUG("enve->recipientInfos.list.count = %d\n", enve->recipientInfos.list.count);
	if (enve->recipientInfos.list.count <= 0) { ret = SOR_IndataErr; goto _end; }
#if 1
//	oid_size = OBJECT_IDENTIFIER_get_arcs(&enve->encryptedContentInfo.contentEncryptionAlgorithmIdentifier.algorithm, 0, sizeof(oid_array[0]), 0);
//	DEBUG("oid_size = %d\n", oid_size);
//	if (oid_size != 4) { ret = SOR_IndataErr; goto _end; }
//	oid_array = (int *)calloc(4, oid_size);
	ret = OBJECT_IDENTIFIER_get_arcs(&enve->encryptedContentInfo.contentEncryptionAlgorithmIdentifier.algorithm, sym_oid, sizeof(sym_oid[0]), sym_oid_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", ret);
	if (ret != SYM_OID_SIZE) { ret = SOR_IndataErr; goto _end; }
	printf("sym_oid = %d,%d,%d,%d,%d,%d,%d\n", sym_oid[0], sym_oid[1],sym_oid[2],sym_oid[3],sym_oid[4],sym_oid[5],sym_oid[6]);
#endif
	if (sym_oid[5] == 102) f_alg = FM_ALG_SM1;
	else if (sym_oid[5] == 103) f_alg = FM_ALG_SSF33;
	else if (sym_oid[5] == 104) f_alg = FM_ALG_SM4;
	else { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }

	if (sym_oid[6] == 1) f_mode = FM_ALGMODE_ECB;
	else if (sym_oid[6] == 2) f_mode = FM_ALGMODE_CBC;
	else if (sym_oid[6] == 4) f_mode = FM_ALGMODE_CFB;
	else if (sym_oid[6] == 3) f_mode = FM_ALGMODE_OFB;
	else if (sym_oid[6] == 7) f_mode = FM_ALGMODE_MAC;
	else { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }

	ret = OBJECT_IDENTIFIER_get_arcs(&enve->recipientInfos.list.array[0]->keyEncryptionAlgorithm.algorithm, ecc_oid, sizeof(ecc_oid[0]), ecc_oid_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", ret);
	if (ret != ECC_OID_SIZE) { ret = SOR_IndataErr; goto _end; }
	if (ecc_oid[0]!=1 || ecc_oid[1]!=2 || ecc_oid[2]!=156 || ecc_oid[3]!=10197 || ecc_oid[4]!=1 || ecc_oid[5]!=301 || ecc_oid[6]!=3) {
		ret = SOR_PARAMETERNOTSUPPORTErr;
		goto _end;
	}
	printf("ecc_oid = %d,%d,%d,%d,%d,%d,%d\n", ecc_oid[0], ecc_oid[1],ecc_oid[2],ecc_oid[3],ecc_oid[4],ecc_oid[5],ecc_oid[6]);

	ret = OBJECT_IDENTIFIER_get_arcs(&enve->encryptedContentInfo.contentType, enve_oid, sizeof(enve_oid[0]), enve_oid_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", ret);
	if (ret != ENVE_OID_SIZE) { ret = SOR_IndataErr; goto _end; }
	if (enve_oid[0]!=1 || enve_oid[1]!=2 || enve_oid[2]!=156 || enve_oid[3]!=10197 || enve_oid[4]!=6 || enve_oid[5]!=1 || enve_oid[6]!=4 || enve_oid[7] != 2 || enve_oid[8] != 3) {
		ret = SOR_IndataErr;
		goto _end;
	}
	DEBUG("*****Now start encrypting******\n");

	ret = SOR_UnknownErr;
	bzero(&f_sm2cipher, sizeof(f_sm2cipher));
	bzero(in_data, in_data_len);

	/* Open Device */
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) goto _end;

	/*	ECC decryption	*/
	DEBUG("enve->recipientInfos.list.array[0]->encryptedKey.size = %d\n", enve->recipientInfos.list.array[0]->encryptedKey.size);
	memcpy(&f_sm2cipher, enve->recipientInfos.list.array[0]->encryptedKey.buf, enve->recipientInfos.list.array[0]->encryptedKey.size);
	f_ret = FM_CPC_ECCDecrypt(f_hd, f_sm2alg, f_sm2key, &f_sm2cipher, NULL, f_sm2out, &f_sm2outlen);
	DEBUG("FM_CPC_ECCDecrypt f_ret = %08X, f_sm2outlen = %d\n", f_ret, f_sm2outlen);
	if (f_ret != FME_OK) goto _close;
	/*	symmetric decryption	*/
	f_ret = FM_CPC_Decrypt(f_hd, f_key, f_alg, f_mode, enve->encryptedContentInfo.encryptedContent->buf, enve->encryptedContentInfo.encryptedContent->size, in_data, &in_data_len, f_sm2out, f_sm2outlen, f_iv, sizeof(f_iv));
	DEBUG("FM_CPC_Decrypt f_ret = %08x, f_plain = %s|f_plainlen = %d\n", f_ret, in_data, in_data_len);
	if (f_ret != FME_OK) { ret = SOR_DECRYPTDATAErr; goto _close; }

	tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, in_data, in_data_len);
	ret = SOR_OK;

_close:
	/* Close Device*/
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "decryptData", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("DecryptData_handle ret = %08x\n", ret);
	res.respond.choice.decryptDataResp.respValue = ret;
	res.respond.choice.decryptDataResp.outData = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = SOR_UnknownErr;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	DEBUG("**********in_data = %p***********\n", in_data);
	if (in_data) {
		free(in_data);
		in_data = NULL;
	}
	DEBUG("*************enve = %p***********\n", enve);
	if (enve) {
		free(enve);
		enve = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int CreateTimeStampRequest_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	unsigned char buff[4096]="";
	int buff_len = sizeof(buff);
	char *out_data = NULL;
	int out_data_len = 0;

	unsigned char hash[32]="";
	int hash_len = sizeof(hash);
	long random=0;
	int flag=1;
	TimeStampReq_t tsq;

	//fm card var
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_createTimeStampRequest;
	res.respond.present = Respond_PR_createTimeStampRequestResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.createTimeStampRequestReq.indata = %s\n", req->request.choice.createTimeStampRequestReq.inData.buf);
	DEBUG("req->request.choice.createTimeStampRequestReq.hashMethod = %08X\n", req->request.choice.createTimeStampRequestReq.hashMethod);
	DEBUG("req->request.choice.createTimeStampRequestReq.certReq = %d\n", req->request.choice.createTimeStampRequestReq.certReq);
	DEBUG("req->request.choice.createTimeStampRequestReq.nonce = %d\n", req->request.choice.createTimeStampRequestReq.nonce);
	if (!req->request.choice.createTimeStampRequestReq.inData.buf || req->request.choice.createTimeStampRequestReq.inData.size<=0)
	{ ret=SOR_IndataErr; goto _end;}
	if (req->request.choice.createTimeStampRequestReq.hashMethod != SGD_SM3) { ret=SOR_PARAMETERNOTSUPPORTErr; goto _end;}

	bzero(&tsq, sizeof(tsq));
	tsq.version = 1;

	/* Hash Operation */
	if (SOR_OK != _fm_sm3(req->request.choice.createTimeStampRequestReq.inData.buf, req->request.choice.createTimeStampRequestReq.inData.size, hash, &hash_len)) {
		ret=SOR_HashErr;
		goto _end;
	}
	/* Gen Random */
	if (req->request.choice.createTimeStampRequestReq.nonce == 1) {
		/* Open Device */
		f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
		DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
		if (f_ret != FME_OK) { ret=SOR_GenRandErr; goto _end;}
		f_ret = FM_CPC_GenRandom(f_hd, sizeof(random), (unsigned char *)&random);
		DEBUG("FM_CPC_GenRandom f_ret = %08x\n", f_ret);
		if (f_ret != FME_OK) { ret=SOR_GenRandErr; FM_CPC_CloseDevice(f_hd);goto _end; }
		tsq.nonce = &random;
		/* Close Device */
		f_ret = FM_CPC_CloseDevice(f_hd);
		DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);
		if (f_ret != FME_OK) { ret=SOR_GenRandErr; FM_CPC_CloseDevice(f_hd);goto _end; }
	}

	ret = OCTET_STRING_fromBuf(&tsq.messageImprint.hashedMessage, (const char *)hash, hash_len);
	if (ret) { ret = SOR_UnknownErr; goto _end; }
	ret = OBJECT_IDENTIFIER_set_arcs(&tsq.messageImprint.hashAlgorithm.algorithm, g_sm3_oid, sizeof(g_sm3_oid[0]), sizeof(g_sm3_oid)/sizeof(g_sm3_oid[0]));
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { ret = SOR_UnknownErr; goto _end; }
	if (req->request.choice.createTimeStampRequestReq.certReq >= 0) {
		tsq.certReq = &flag;
	}
	enc_ret = der_encode_to_buffer(&asn_DEF_TimeStampReq, &tsq, buff, buff_len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
	if (enc_ret.encoded == -1) { ret = SOR_UnknownErr; goto _end; }

	out_data_len = (int)(enc_ret.encoded*1.5)+4;
	out_data = (unsigned char *)calloc(1, out_data_len);
	if (!out_data) { ret = SOR_MemoryErr; goto _end; }
	ret = base64_encode(out_data, &out_data_len, buff, enc_ret.encoded);
	DEBUG("base64_encode ret = %d, out_data_len = %d\n", ret, out_data_len);
	if (ret) { ret = SOR_UnknownErr; goto _end; }
	tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, out_data, out_data_len);
	ret = SOR_OK;

_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "createTimeStampRequest", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("CreateTimeStampRequest_handle ret = %08x\n", ret);
	res.respond.choice.createTimeStampRequestResp.respValue = ret;
	res.respond.choice.createTimeStampRequestResp.outData = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, &tsq.messageImprint.hashedMessage, 1);
	if (out_data) {
		free(out_data);
		out_data = NULL;
	}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int CreateTimeStampResponse_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	asn_dec_rval_t dec_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL, *freetext = NULL, *raw = NULL;
	unsigned char hash[32]="";
	int hash_len = sizeof(hash);
	unsigned char sm3_cert_hash[32]="";
	int sm3_cert_hash_len = sizeof(sm3_cert_hash);
	unsigned char *raw_data = NULL;
	int raw_len = 0;
	char dn[512]="", sn[64]="", appname[64]="";
	e_PKIFailureInfo failinfo = 0;
	int containerIndex = 0;
	TimeStampReq_t *tsq = NULL;
	int *hash_array = NULL;
	int hash_size = 0;
	TimeStampResq_t tsresp;
	ContentInfo_t content; // for timeStampToken
	SignedData_t sdata;		// for timeStampToken content
	AlgorithmIdentifier_t alg;
	ExtendedCertificateOrCertificate_t cert;
	ExtendedCertificatesAndCertificates_t certs;
	SignerInfo_t sinfo;
	Attribute_t	 sinfo_attr;
	SigningCertificateV2_t	sinfo_attr_value;
	ANY_t *psinfo_attr_value = NULL;
	ESSCertIDv2_t	sinfo_cert;
	IssuerSerial_t	sinfo_cert_is;
	GeneralName_t	general_name;
	Attributes_t sinfo_attrs;
	int hash_method = SGD_SM3;
	Certificate_t *x=NULL;
	unsigned char cert_buf[2048]="";
	int cert_len = sizeof(cert_buf);
	unsigned char buff[4096]="";
	int buff_len = sizeof(buff);
	char *out_data = NULL;
	int out_data_len = 0;
	FM_ECC_Signature ecc_sign;

	//fm card var
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;
	FM_U32	f_alg = FM_ALG_SM2_1;
	FM_HKEY f_sm2key = 0;

	bzero(&tsresp, sizeof(tsresp));
	bzero(&content, sizeof(content));
	bzero(&sdata, sizeof(sdata));
	bzero(&alg, sizeof(alg));
	bzero(&cert, sizeof(cert));
	bzero(&certs, sizeof(certs));
	bzero(&sinfo, sizeof(sinfo));
	bzero(&sinfo_attr, sizeof(sinfo_attr));
	bzero(&sinfo_attr_value, sizeof(sinfo_attr_value));
	bzero(&sinfo_cert, sizeof(sinfo_cert));
	bzero(&sinfo_cert_is, sizeof(sinfo_cert_is));
	bzero(&general_name, sizeof(general_name));
	bzero(&sinfo_attrs, sizeof(sinfo_attrs));
	bzero(&ecc_sign, sizeof(ecc_sign));
#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_createTimeStampResponse;
	res.respond.present = Respond_PR_createTimeStampResponseResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.createTimeStampResponseReq.timeStampRequest = %s\n", req->request.choice.createTimeStampResponseReq.timeStampRequest.buf);
	DEBUG("req->request.choice.createTimeStampResponseReq.containerName = %s\n", req->request.choice.createTimeStampResponseReq.containerName.buf);
	containerIndex = get_containerIndex_by_containerName(req->request.choice.createTimeStampResponseReq.containerName.buf);
	DEBUG("containerIndex = %d\n", containerIndex);
	if (containerIndex < 0) { ret = SOR_KeyNotFountErr; goto _end; }
	f_sm2key = (FM_HKEY)(FM_UP)(containerIndex+128);

	/* Parse the TimeStampReq valid or not */
	dec_ret = ber_decode(NULL, &asn_DEF_TimeStampReq, (void **)&tsq, req->request.choice.createTimeStampResponseReq.timeStampRequest.buf, req->request.choice.createTimeStampResponseReq.timeStampRequest.size);
	DEBUG("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code != RC_OK) { ret = SOR_IndataErr; goto _end; }

	/* Get the hash method */
	hash_size = OBJECT_IDENTIFIER_get_arcs(&tsq->messageImprint.hashAlgorithm.algorithm, 0, sizeof(int), 0);
	DEBUG("hash_size = %d\n", hash_size);
	if (hash_size != 6) 
	{ tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_badAlg; ret = SOR_IndataErr; goto _ts; }
	hash_array = (int *)calloc(sizeof(int), hash_size);
	if (!hash_array) { ret = SOR_MemoryErr; goto _end; }
	ret = OBJECT_IDENTIFIER_get_arcs(&tsq->messageImprint.hashAlgorithm.algorithm, hash_array, sizeof(hash_array[0]), hash_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", ret);
	if (ret == hash_size && hash_array[0]==g_sm3_oid[0] && hash_array[1]==g_sm3_oid[1] && hash_array[2]==g_sm3_oid[2] 
			&& hash_array[3]==g_sm3_oid[3] && hash_array[4]==g_sm3_oid[4] && hash_array[5]==g_sm3_oid[5]) {
		hash_method = SGD_SM3;
	} else if (ret == hash_size && hash_array[0]==g_sha1_oid[0] && hash_array[1]==g_sha1_oid[1] && hash_array[2]==g_sha1_oid[2] 
			&& hash_array[3]==g_sha1_oid[3] && hash_array[4]==g_sha1_oid[4] && hash_array[5]==g_sha1_oid[5]) {
		hash_method = SGD_SHA1;
	} else { 
		tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_badAlg; ret = SOR_IndataErr; goto _ts; 
	}

	/* Set timeStampToken contentType */
	ret = OBJECT_IDENTIFIER_set_arcs(&content.contentType, g_sign_oid, sizeof(g_sign_oid[0]),sizeof(g_sign_oid)/sizeof(g_sign_oid[0]));
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }

	/* Set timeStampToken content(SignedData) digestAlgorithms */
	sdata.version = 0;
	ret = OBJECT_IDENTIFIER_set_arcs(&alg.algorithm, hash_array, sizeof(int), hash_size);
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	ret = asn_set_add(&sdata.digestAlgorithms.list, &alg);
		DEBUG("asn_set_add ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }

	/* Set timeStampToken content(SignedData) contentInfo */
	ret = OBJECT_IDENTIFIER_set_arcs(&sdata.contentInfo.contentType, g_data_oid, sizeof(g_data_oid[0]), sizeof(g_data_oid)/sizeof(g_data_oid[0]));
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	raw_len = tsq->messageImprint.hashedMessage.size + res.respTime.size;
	raw_data = (unsigned char *)calloc(1, raw_len);
	DEBUG("*****************\n");
	if (!raw_data) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	DEBUG("*****************\n");
	memcpy(raw_data, tsq->messageImprint.hashedMessage.buf, tsq->messageImprint.hashedMessage.size);
	memcpy(raw_data+tsq->messageImprint.hashedMessage.size, res.respTime.buf, res.respTime.size);
	DEBUG("raw_data = %s\n", raw_data);
	raw = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, raw_data, raw_len);
	sdata.contentInfo.content = ANY_new_fromType(&asn_DEF_OCTET_STRING, raw);
	if (!sdata.contentInfo.content) {
		tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts;
	}
		/* Hash Operation */
	if (SOR_OK != _fm_sm3(raw_data, raw_len, hash, &hash_len)) {
		ret=SOR_HashErr;
		goto _end;
	}
		/* Open Device */
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK)
	{ tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
		/* ECC Sign Operation */
	f_ret = FM_CPC_ECCSign(f_hd, f_alg, f_sm2key, hash, hash_len, NULL, &ecc_sign);
	DEBUG("FM_CPC_ECCSign f_ret = %08x\n", f_ret);
	FILE *fp = NULL;
	fp = fopen("signdata", "wb");
	fwrite(&ecc_sign, sizeof(ecc_sign), 1, fp);
	fclose(fp);
	if (f_ret != FME_OK)
	{ 
		f_ret = FM_CPC_CloseDevice(f_hd);
		tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; 
	}
		/* Close Device */
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK) { ret=PKIFailureInfo_systemFailure; goto _end; }
	fp = fopen("raw_data", "wb");
	fwrite(raw->buf, 1, raw->size, fp);
	fclose(fp);
	/* Set timeStampToken content(SignedData) certificates */
	ret = get_bin_cert_by_index(cert_buf, &cert_len, containerIndex);
	DEBUG("get_bin_cert_by_index ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_addInfoNotAvailble; ret = SOR_IndataErr; goto _ts; }
	dec_ret = ber_decode(NULL, &asn_DEF_Certificate, (void **)&x, cert_buf, cert_len);
	DEBUG("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code != RC_OK) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_addInfoNotAvailble; ret = SOR_IndataErr; goto _ts; }
	if (tsq->certReq && *(tsq->certReq)>=0) {
		cert.choice.certificate = *x;
		cert.present = ExtendedCertificateOrCertificate_PR_certificate;
		ret = asn_set_add(&certs.list, &cert);
		DEBUG("asn_set_add ret = %d\n", ret);
		if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
		sdata.certificates = &certs;
	}
	/************** Set timeStampToken content(SignedData) signerInfos ***************/
		// signerInfo IssuerAndSerialNumber
	mysql_parse_cert_by_index(containerIndex, dn, sn, appname);
	DEBUG("sn = %s|%ld\n", sn, atol(sn));
	sinfo.issuerAndSerialNumber.issuer = x->tbsCertificate.issuer;
	sinfo.issuerAndSerialNumber.serialNumber = atol(sn);
		// signerInfo DigestAlgorithmIdentifier
	ret = OBJECT_IDENTIFIER_set_arcs(&sinfo.digestAlgorithm.algorithm, hash_array, sizeof(int), hash_size);
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
		// signerInfo DigestEncryptionAlgorithmIdentifier
	ret = OBJECT_IDENTIFIER_set_arcs(&sinfo.digestEncryptionAlgorithm.algorithm, g_sm2_1_oid, sizeof(g_sm2_1_oid[0]), sizeof(g_sm2_1_oid)/sizeof(g_sm2_1_oid[0]));
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
		// signerInfo EncryptedDigest
	ret = OCTET_STRING_fromBuf(&sinfo.encryptedDigest, (const char*)&ecc_sign, sizeof(ecc_sign));
	DEBUG("OCTET_STRING_fromBuf ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
		// Set signerInfo Attribute OID(SigningCertificateV2)
	ret = OBJECT_IDENTIFIER_set_arcs(&sinfo_attr.type, g_signcertV2_oid, sizeof(g_signcertV2_oid[0]), sizeof(g_signcertV2_oid)/sizeof(g_signcertV2_oid[0]));
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
		/* Set SigningCertificateV2 Attribute Value(ESSCertv2) */
			/* Set ESSCertv2 hashAlgorithm */
	ret = OBJECT_IDENTIFIER_set_arcs(&sinfo_cert.hashAlgorithm.algorithm,g_sm3_oid,sizeof(int),sizeof(g_sm3_oid)/sizeof(g_sm3_oid[0]));
	DEBUG("OBJECT_IDENTIFIER_set_arcs ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
			/* Set ESSCertv2 certHash */
			// SM3 Hash Operation
	if (SOR_OK != _fm_sm3(cert_buf, cert_len, sm3_cert_hash, &sm3_cert_hash_len)) 
	{ tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_HashErr; goto _ts; }
	ret = OCTET_STRING_fromBuf(&sinfo_cert.certHash, sm3_cert_hash, sm3_cert_hash_len);
	DEBUG("OCTET_STRING_fromBuf RET = %d\n", ret);
#ifdef _DEBUG_
	fp = fopen("cert_hash", "wb");
	fwrite(sm3_cert_hash, 1, sm3_cert_hash_len, fp);
	fclose(fp);
#endif
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
			/* Set ESSCertv2 IssuerSerial */
	sinfo_cert_is.serialNumber = atol(sn);
	general_name.present = GeneralName_PR_directoryName;
	general_name.choice.directoryName = x->tbsCertificate.issuer;
	ret = asn_set_add(&sinfo_cert_is.issuer.list, &general_name);
	DEBUG("asn_set_add ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	sinfo_cert.issuerSerial = &sinfo_cert_is;
	ret = asn_set_add(&sinfo_attr_value.certs.list, &sinfo_cert);
	DEBUG("asn_set_add ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
		/* Set Attribute Values */
	psinfo_attr_value = ANY_new_fromType(&asn_DEF_SigningCertificateV2, &sinfo_attr_value);
	if (!psinfo_attr_value) {
		tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts;
	}
	ret = asn_set_add(&sinfo_attr.values.list, psinfo_attr_value);
	DEBUG("asn_set_add ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }

	ret = asn_set_add(&sinfo_attrs.list, &sinfo_attr);
	DEBUG("asn_set_add ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	sinfo.authenticatedAttributes = &sinfo_attrs;

	ret = asn_set_add(&sdata.signerInfos.list, &sinfo);
	DEBUG("asn_set_add ret = %d\n", ret);
	if (ret) { tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts; }
	content.content = ANY_new_fromType(&asn_DEF_SignedData, &sdata);
	if (!content.content) {
		tsresp.status.status=PKIStatus_rejection; failinfo = PKIFailureInfo_systemFailure; ret = SOR_IndataErr; goto _ts;
	}

_ts:
	if (tsresp.status.status!=PKIStatus_granted && tsresp.status.status!=PKIStatus_grantedWithMods) {
		tsresp.status.failInfo = &failinfo;
	}else{
		tsresp.timeStampToken = &content;
	}
	enc_ret = der_encode_to_buffer(&asn_DEF_TimeStampResq, &tsresp, buff, buff_len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
	if (enc_ret.encoded == -1) { ret = SOR_UnknownErr; goto _end; }

	out_data_len = (int)(enc_ret.encoded*1.5)+4;
	out_data = (unsigned char *)calloc(1, out_data_len);
	if (!out_data) { ret = SOR_MemoryErr; goto _end; }
	ret = base64_encode(out_data, &out_data_len, buff, enc_ret.encoded);
	DEBUG("base64_encode ret = %d, out_data_len = %d\n", ret, out_data_len);
	if (ret) { ret = SOR_UnknownErr; goto _end; }
	else tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, out_data, out_data_len);
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "createTimeStampResponse", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("CreateTimeStampResponse_handle ret = %08x\n", ret);
	res.respond.choice.createTimeStampResponseResp.respValue = ret;
	res.respond.choice.createTimeStampResponseResp.outData = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, raw, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_ANY, sdata.contentInfo.content, 0);
	OCTET_STRING_free(&asn_DEF_ANY, psinfo_attr_value, 0);
	OCTET_STRING_free(&asn_DEF_ANY, content.content, 0);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, &sinfo_cert.certHash, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, &sinfo.encryptedDigest, 1);
	if(tsq) { free(tsq);tsq=NULL; }
	if (hash_array) { free(hash_array); hash_array = NULL; }
	if (out_data) { free(out_data); out_data = NULL; }
	if (raw_data) { free(raw_data); raw_data = NULL; }
	if (x) { free(x); x=NULL; }
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int VerifyTimeStamp_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = GM_SUCCESS;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	asn_dec_rval_t dec_ret;
	GeneralizedTime_t *tp = NULL;
	TimeStampResq_t *tsr = NULL;
	SignedData_t *sdata = NULL;		// for timeStampToken content
	OCTET_STRING_t *raw = NULL;
	OCTET_STRING_t *cert_hash_tmp = NULL;
	SigningCertificateV2_t	*sinfo_attr_valueV2 = NULL;
	SigningCertificate_t	*sinfo_attr_value = NULL;
	int sign_oid[9] = {0};
	int sign_size = 9;
	int hash_array[6] = {0};
	int hash_size = 6;
	int data_oid[9] = {0};
	int data_size = 9;
	int attr_oid[9] = {0};
	int attr_size = sizeof(attr_oid);
	int *cert_hash_oid = NULL;
	int cert_hash_len = 0;
	unsigned char hash[32]="";
	int hash_len = sizeof(hash);
	int hash_method = SGD_SM3;
	int cert_hash_method = SGD_SM3;
	int keyIndex = 1;
	FM_ECC_Signature ecc_sign;
	//fm card var
	FM_U32 f_ret = FME_OK;
	FM_HANDLE f_hd;
	FM_U8 f_id = 0;
	FM_U32	f_type = FM_DEV_TYPE_PCIE_1_0X;
	FM_U32	f_flag = FM_OPEN_MULTITHREAD;
	FM_U32	f_alg = FM_ALG_SM2_1;
	FM_HKEY f_sm2key = 0;

	bzero(&ecc_sign, sizeof(ecc_sign));
#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_verifyTimeStamp;
	res.respond.present = Respond_PR_verifyTimeStampResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.verifyTimeStampReq.inData = %s|size = %d\n", req->request.choice.verifyTimeStampReq.inData.buf, req->request.choice.verifyTimeStampReq.inData.size);
	DEBUG("req->request.choice.verifyTimeStampReq.tsResponseData = %s| size = %d\n", req->request.choice.verifyTimeStampReq.tsResponseData.buf, req->request.choice.verifyTimeStampReq.tsResponseData.size);

	/* Parse the TimeStampResq valid or not */
	dec_ret = ber_decode(NULL, &asn_DEF_TimeStampResq, (void **)&tsr, req->request.choice.verifyTimeStampReq.tsResponseData.buf, req->request.choice.verifyTimeStampReq.tsResponseData.size);
	DEBUG("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code != RC_OK) { ret = SOR_IndataErr; goto _end; }

	/* Get the content type (MUST be signedData type)*/
	sign_size = OBJECT_IDENTIFIER_get_arcs(&tsr->timeStampToken->contentType, sign_oid, sizeof(sign_oid[0]), sizeof(sign_oid)/sizeof(sign_oid[0]));
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", sign_size);
	DEBUG("%d,%d,%d,%d,%d,%d,%d,%d,%d\n", sign_oid[0], sign_oid[1], sign_oid[2], sign_oid[3], sign_oid[4], sign_oid[5], sign_oid[6], sign_oid[7], sign_oid[8]);
#if 1
	if (sign_size!=9 || sign_oid[0]!=g_sign_oid[0] || sign_oid[1]!=g_sign_oid[1] || sign_oid[2]!=g_sign_oid[2] || sign_oid[3]!=g_sign_oid[3] || sign_oid[4]!=g_sign_oid[4] || sign_oid[5]!=g_sign_oid[5] || sign_oid[6]!=g_sign_oid[6] || sign_oid[7]!=g_sign_oid[7] || sign_oid[8]!=g_sign_oid[8])
	{ ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }
	ret = ANY_to_type(tsr->timeStampToken->content, &asn_DEF_SignedData, (void **)&sdata);
	DEBUG("ANY_to_type ret = %d\n", ret);
	if (ret) { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }
	/* Get the hash method (SUPPORT SM3 and SHA1)*/
	hash_size = OBJECT_IDENTIFIER_get_arcs(&sdata->digestAlgorithms.list.array[0]->algorithm, hash_array, sizeof(hash_array[0]), hash_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", hash_size);
	if (6 == hash_size && hash_array[0]==g_sm3_oid[0] && hash_array[1]==g_sm3_oid[1] && hash_array[2]==g_sm3_oid[2] 
			&& hash_array[3]==g_sm3_oid[3] && hash_array[4]==g_sm3_oid[4] && hash_array[5]==g_sm3_oid[5]) {
		hash_method = SGD_SM3;
	} else if (6 == hash_size && hash_array[0]==g_sha1_oid[0] && hash_array[1]==g_sha1_oid[1] && hash_array[2]==g_sha1_oid[2] 
			&& hash_array[3]==g_sha1_oid[3] && hash_array[4]==g_sha1_oid[4] && hash_array[5]==g_sha1_oid[5]) {
		hash_method = SGD_SHA1;
	} else { 
		ret = SOR_IndataErr; goto _end; 
	}
	/* Get the contentInfo (MUST be Data type)*/
	data_size = OBJECT_IDENTIFIER_get_arcs(&sdata->contentInfo.contentType, data_oid, sizeof(data_oid[0]), data_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", data_size);
	if (9 != data_size || data_oid[0]!=g_data_oid[0] || data_oid[1]!=g_data_oid[1] || data_oid[2]!=g_data_oid[2] || data_oid[3]!=g_data_oid[3] || data_oid[4]!=g_data_oid[4] || data_oid[5]!=g_data_oid[5] || data_oid[6]!=g_data_oid[6] || data_oid[7]!=g_data_oid[7] || data_oid[8]!=g_data_oid[8])
	if (ret) { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }
	ret = ANY_to_type(sdata->contentInfo.content, &asn_DEF_OCTET_STRING, (void **)&raw);
	DEBUG("ANY_to_type ret = %d\n", ret);
	if (ret) { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }
		/* Hash Operation */
	if (hash_method == SGD_SHA1) {
		if (SOR_OK != _fm_sha1(raw->buf, raw->size, hash, &hash_len)) {
			ret=SOR_HashErr;
			goto _end;
		}
	} else {
		if (SOR_OK != _fm_sm3(raw->buf, raw->size, hash, &hash_len)) {
			ret=SOR_HashErr;
			goto _end;
		}
	}
	DEBUG("hash_len = %d\n", hash_len);
	DEBUG("sdata->signerInfos.list.count = %d\n", sdata->signerInfos.list.count);
	if (sdata->signerInfos.list.count <= 0) { ret = SOR_IndataErr; goto _end; }
	memcpy(&ecc_sign, sdata->signerInfos.list.array[0]->encryptedDigest.buf, sdata->signerInfos.list.array[0]->encryptedDigest.size);

	/* Get SigningCertificateV2/SigningCertificate info */
	DEBUG("count = %d\n", sdata->signerInfos.list.array[0]->authenticatedAttributes->list.count);
	if (sdata->signerInfos.list.array[0]->authenticatedAttributes->list.count <= 0) { ret = SOR_IndataErr; goto _end; }

	attr_size = OBJECT_IDENTIFIER_get_arcs(&sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->type, attr_oid, sizeof(attr_oid[0]), attr_size);
	DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", attr_size);
	if (9==attr_size && attr_oid[0]==g_signcertV2_oid[0] && attr_oid[1]==g_signcertV2_oid[1] && attr_oid[2]==g_signcertV2_oid[2] 
			&& attr_oid[3]==g_signcertV2_oid[3] && attr_oid[4]==g_signcertV2_oid[4] && attr_oid[5]==g_signcertV2_oid[5] 
			&& attr_oid[6]==g_signcertV2_oid[6] && attr_oid[7]==g_signcertV2_oid[7] && attr_oid[8]==g_signcertV2_oid[8]) {
		/* Attribute type is SigningCertificateV2 */
		DEBUG("count = %d\n", sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->values.list.count);
		if (sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->values.list.count <= 0)
			{ ret = SOR_IndataErr; goto _end; }
		ret = ANY_to_type(sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->values.list.array[0], &asn_DEF_SigningCertificateV2, (void **)&sinfo_attr_valueV2);
		DEBUG("ANY_to_type ret = %d, sinfo_attr_valueV2 = %p\n", ret, sinfo_attr_valueV2);
		if (ret) 
			{ ret = SOR_IndataErr; goto _end; }
		DEBUG("sinfo_attr_valueV2->certs.list.count = %d\n", sinfo_attr_valueV2->certs.list.count);
		if (sinfo_attr_valueV2->certs.list.count <= 0)
			{ ret = SOR_IndataErr; goto _end; }
		cert_hash_len = OBJECT_IDENTIFIER_get_arcs(&sinfo_attr_valueV2->certs.list.array[0]->hashAlgorithm.algorithm, 0, sizeof(int), 0);
		DEBUG("cert_hash_len = %d\n", cert_hash_len);
		if (cert_hash_len<=0) { ret = SOR_IndataErr; goto _end; }
		cert_hash_oid = (int *)calloc(sizeof(int), cert_hash_len);
		if (!cert_hash_oid) { ret = SOR_MemoryErr; goto _end; }
		cert_hash_len = OBJECT_IDENTIFIER_get_arcs(&sinfo_attr_valueV2->certs.list.array[0]->hashAlgorithm.algorithm, cert_hash_oid, sizeof(int), cert_hash_len);
		DEBUG("cert_hash_len = %d\n", cert_hash_len);
		if (cert_hash_len == 6 && cert_hash_oid[0]==g_sm3_oid[0] && cert_hash_oid[1]==g_sm3_oid[1] && cert_hash_oid[2]==g_sm3_oid[2] 
				&& cert_hash_oid[3]==g_sm3_oid[3] && cert_hash_oid[4]==g_sm3_oid[4] && cert_hash_oid[5]==g_sm3_oid[5]) {
			cert_hash_method = SGD_SM3;
		} else if (cert_hash_len==6&&cert_hash_oid[0]==g_sha1_oid[0]&&cert_hash_oid[1]==g_sha1_oid[1]&&cert_hash_oid[2]==g_sha1_oid[2]
				&& cert_hash_oid[3]==g_sha1_oid[3] && cert_hash_oid[4]==g_sha1_oid[4] && cert_hash_oid[5]==g_sha1_oid[5]) {
			cert_hash_method = SGD_SHA1;
		} else { 
			ret = SOR_PARAMETERNOTSUPPORTErr; 
			goto _end; 
		}
		cert_hash_tmp = &sinfo_attr_valueV2->certs.list.array[0]->certHash;
	} else if (9==attr_size && attr_oid[0]==g_signcert_oid[0] && attr_oid[1]==g_signcert_oid[1] && attr_oid[2]==g_signcert_oid[2] 
			&& attr_oid[3]==g_signcert_oid[3] && attr_oid[4]==g_signcert_oid[4] && attr_oid[5]==g_signcert_oid[5] 
			&& attr_oid[6]==g_signcert_oid[6] && attr_oid[7]==g_signcert_oid[7] && attr_oid[8]==g_signcert_oid[8]) {
		/* Attribute type is SigningCertificate */
		cert_hash_method = SGD_SHA1;
		DEBUG("count = %d\n", sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->values.list.count);
		if (sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->values.list.count <= 0)
			{ ret = SOR_IndataErr; goto _end; }
		ret = ANY_to_type(sdata->signerInfos.list.array[0]->authenticatedAttributes->list.array[0]->values.list.array[0], &asn_DEF_SigningCertificate, (void **)&sinfo_attr_value);
		DEBUG("ANY_to_type ret = %d, sinfo_attr_value = %p\n", ret, sinfo_attr_value);
		if (ret) 
			{ ret = SOR_IndataErr; goto _end; }
		cert_hash_tmp = &sinfo_attr_value->certs.list.array[0]->certHash;
	} else { 
		ret = SOR_PARAMETERNOTSUPPORTErr; 
		goto _end; 
	}

	/* Get the keyIndex by certificate hash in ESSCertIDv2*/
	keyIndex = get_index_by_certHash(cert_hash_method, cert_hash_tmp->buf, cert_hash_tmp->size);
	DEBUG("keyIndex = %d\n", keyIndex);
	if (keyIndex <= 0) { ret = SOR_CertNotFountErr; goto _end; }
	f_sm2key = (FM_HKEY)(FM_UP)(keyIndex+128);

#ifdef _DEBUG_
	FILE *fp;
	fp = fopen("verify_cert_hash", "wb");
	fwrite(sinfo_attr_valueV2->certs.list.array[0]->certHash.buf, 1, sinfo_attr_valueV2->certs.list.array[0]->certHash.size, fp);
	fclose(fp);
#endif
		/* Open Device */
	f_ret = FM_CPC_OpenDevice(&f_id, f_type, f_flag, &f_hd);
	DEBUG("FM_CPC_OpenDevice f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK)
	{ ret = SOR_UnknownErr; goto _end; }
	if (f_ret != FME_OK) { ret=SOR_HashErr; FM_CPC_CloseDevice(f_hd);goto _end; }
		/* ECC Verify Operation */
	f_ret = FM_CPC_ECCVerify(f_hd, f_alg, f_sm2key, NULL, hash, hash_len, &ecc_sign);
	DEBUG("FM_CPC_ECCVerify f_ret = %08x\n", f_ret);
	if (f_ret != FME_OK)
	{ f_ret = FM_CPC_CloseDevice(f_hd); ret = SOR_VERIFYSIGNDATAErr; goto _end; }
		/* Close Device */
	f_ret = FM_CPC_CloseDevice(f_hd);
	DEBUG("FM_CPC_CloseDevice f_ret = %08x\n", f_ret);
#endif
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "verifyTimeStamp", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("VerifyTimeStamp_handle ret = %08x\n", ret);
	res.respond.choice.verifyTimeStampResp.respValue = ret;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, raw, 0);
	SEQUENCE_free(&asn_DEF_SignedData, sdata, 0);
	SEQUENCE_free(&asn_DEF_SigningCertificateV2, sinfo_attr_valueV2, 0);
	SEQUENCE_free(&asn_DEF_SigningCertificate, sinfo_attr_value, 0);
	SEQUENCE_free(&asn_DEF_TimeStampResq, tsr, 0);
#if 1
	if (cert_hash_oid) {
		free(cert_hash_oid);
		cert_hash_oid = NULL;
	}
#endif
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}
static int GetTimeStampInfo_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = SOR_OK;
	SVSRespond_t res;
	time_t now;
	struct tm *cur_tm;
	asn_enc_rval_t enc_ret;
	asn_dec_rval_t dec_ret;
	GeneralizedTime_t *tp = NULL;
	OCTET_STRING_t *tmp = NULL;
	unsigned char *in_data = NULL;
	int in_data_len = 0;
	TimeStampResq_t *tsr = NULL;
	SignedData_t *sdata = NULL;		// for timeStampToken content
	OCTET_STRING_t *raw = NULL;
	int sign_oid[9] = {0};
	int sign_size = 9;
	int *hash_array = NULL;
	int hash_size = 0;
	int data_oid[9] = {0};
	int data_size = 9;
	unsigned char buff[2048]="";
	int buff_len = sizeof(buff);

#ifdef _TIME_
	struct timeval tv_begin, tv_end;
	gettimeofday(&tv_begin, NULL);
#endif
	/*for response*/
	bzero(&res, sizeof(res));
	res.version = 0;
	res.respType = RespType_getTimeStampInfo;
	res.respond.present = Respond_PR_getTimeStampInfoResp;
	now = time(NULL);
	cur_tm = localtime(&now);
	tp = asn_time2GT(&res.respTime, cur_tm, 1);

	DEBUG("req->request.choice.getTimeStampInfoReq.tsResponseData = %s\n", req->request.choice.getTimeStampInfoReq.tsResponseData.buf);
	DEBUG("req->request.choice.getTimeStampInfoReq.type = %d\n", req->request.choice.getTimeStampInfoReq.type);

	if (req->request.choice.getTimeStampInfoReq.type!=1 && req->request.choice.getTimeStampInfoReq.type!=2 && req->request.choice.getTimeStampInfoReq.type!=3) { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }

	/* Base64 Decode */
	in_data_len = req->request.choice.getTimeStampInfoReq.tsResponseData.size;
	in_data = (unsigned char *)calloc(1, in_data_len);
	if (!in_data) { ret = SOR_MemoryErr; goto _end; }
	ret = base64_decode(in_data, &in_data_len, req->request.choice.getTimeStampInfoReq.tsResponseData.buf, req->request.choice.getTimeStampInfoReq.tsResponseData.size);
	DEBUG("base64_decode ret = %d\n", ret);
	if (ret) { ret = SOR_ProviderTypeErr; goto _end; }

	/* Parse the TimeStampResq valid or not */
	dec_ret = ber_decode(NULL, &asn_DEF_TimeStampResq, (void **)&tsr, in_data, in_data_len);
	DEBUG("dec_ret.code = %d\n", dec_ret.code);
	if (dec_ret.code != RC_OK) { ret = SOR_IndataErr; goto _end; }

	/* Get the timeStampToken content(SignedData)*/
	ret = ANY_to_type(tsr->timeStampToken->content, &asn_DEF_SignedData, (void **)&sdata);
	DEBUG("ANY_to_type ret = %d\n", ret);
	if (ret) { ret = SOR_PARAMETERNOTSUPPORTErr; goto _end; }
	/* Get the timeStampToken content(SignedData) contentInfo Including hash & timestamp */
	ret = ANY_to_type(sdata->contentInfo.content, &asn_DEF_OCTET_STRING, (void **)&raw);
	DEBUG("ANY_to_type ret = %d|raw = %s|size = %d\n", ret, raw->buf, raw->size);

	if (req->request.choice.getTimeStampInfoReq.type == 1) {
		hash_size = OBJECT_IDENTIFIER_get_arcs(&sdata->digestAlgorithms.list.array[0]->algorithm, 0, sizeof(int), 0);
		DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", hash_size);
		if (hash_size <= 0) { ret = SOR_AlgoTypeErr; goto _end;}
		hash_array = (int *)calloc(sizeof(int), hash_size);
		if (!hash_array) {ret = SOR_MemoryErr; goto _end;}
		hash_size = OBJECT_IDENTIFIER_get_arcs(&sdata->digestAlgorithms.list.array[0]->algorithm, hash_array, sizeof(hash_array[0]), hash_size);
		DEBUG("OBJECT_IDENTIFIER_get_arcs RET = %d\n", hash_size);
		DEBUG("%d,%d,%d,%d,%d,%d\n", hash_array[0], hash_array[1], hash_array[2], hash_array[3], hash_array[4], hash_array[5]);
		if (6 == hash_size && hash_array[0]==g_sm3_oid[0] && hash_array[1]==g_sm3_oid[1] && hash_array[2]==g_sm3_oid[2] 
			&& hash_array[3]==g_sm3_oid[3] && hash_array[4]==g_sm3_oid[4] && hash_array[5]==g_sm3_oid[5]) // sm3 hash algorithm oid
			tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, raw->buf+32, raw->size-32);
		else if (6 == hash_size && hash_array[0]==g_sha1_oid[0] && hash_array[1]==g_sha1_oid[1] && hash_array[2]==g_sha1_oid[2] 
			&& hash_array[3]==g_sha1_oid[3] && hash_array[4]==g_sha1_oid[4] && hash_array[5]==g_sha1_oid[5]) // sha1 hash algorithm oid
			tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, raw->buf+20, raw->size-20);
		else 
			ret = SOR_AlgoTypeErr;
	} else if (req->request.choice.getTimeStampInfoReq.type == 2) {
		if (sdata->signerInfos.list.count <= 0)
			ret = SOR_IndataErr;
		tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, sdata->signerInfos.list.array[0]->encryptedDigest.buf, sdata->signerInfos.list.array[0]->encryptedDigest.size);
	} else if (req->request.choice.getTimeStampInfoReq.type == 3) {
		if (!sdata->certificates || sdata->certificates->list.count<=0)
			ret = SOR_CertNotFountErr;
		else {
			if (sdata->certificates->list.array[0]->present == ExtendedCertificateOrCertificate_PR_certificate)
				enc_ret = der_encode_to_buffer(&asn_DEF_Certificate, &sdata->certificates->list.array[0]->choice.certificate, buff, buff_len);
			else if (sdata->certificates->list.array[0]->present == ExtendedCertificateOrCertificate_PR_extendedCertificate)
				enc_ret = der_encode_to_buffer(&asn_DEF_ExtendedCertificate, &sdata->certificates->list.array[0]->choice.extendedCertificate, buff, buff_len);
			else { ret=SOR_IndataErr; goto _end; }
			DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
			if (enc_ret.encoded == -1) {
				ret = SOR_CERTENCODEErr;
			} else {
				tmp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, buff, enc_ret.encoded);
			}
		}
	}
_end:
#ifdef _LOG_
	mysql_svs_interface_log_operate(fd, g_appname, "getTimeStampInfo", cur_tm, g_dn, g_sn, ret, "", "");
#endif
	DEBUG("GetTimeStampInfo_handle ret = %08x\n", ret);
	res.respond.choice.getTimeStampInfoResp.respValue = ret;
	res.respond.choice.getTimeStampInfoResp.info = tmp;

	enc_ret = der_encode_to_buffer(&asn_DEF_SVSRespond, &res, buf, *len);
	DEBUG("enc_ret.encoded = %d\n", enc_ret.encoded);
   	if(enc_ret.encoded  == -1) {
       	DEBUG_Log("[%s|%s|%d]:Could not encode SVSRespond (at %s)\n", __FILE__, __func__, __LINE__, 
           	enc_ret.failed_type ? enc_ret.failed_type->name : "unknown");
		ret = GM_SYSTEM_FALURE;
//		bzero(buf, *len);
   	}
	*len = enc_ret.encoded;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, tmp, 0);
	OCTET_STRING_free(&asn_DEF_GeneralizedTime, tp, 1);
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, raw, 0);
	SEQUENCE_free(&asn_DEF_SignedData, sdata, 0);
	SEQUENCE_free(&asn_DEF_TimeStampResq, tsr, 0);
	if (in_data) { free(in_data); in_data = NULL; }
	if (hash_array) {free(hash_array); hash_array=NULL;}
#ifdef _TIME_
	gettimeofday(&tv_end, NULL);
	printf("%s interval [%.6fs]\n", __func__, tv_end.tv_sec-tv_begin.tv_sec+(tv_end.tv_usec-tv_begin.tv_usec)*0.000001);
#endif

	return ret;
}

static int svs_handle(int fd, SVSRequest_t *req, char * buf, int * len)
{
	int ret = 0;

	DEBUG("*len = %d\n", *len);
	pthread_mutex_lock(&g_lock__);
	switch(req->reqType) {
		case ReqType_exportCert:
			ret = ExportCert_handle(fd, req, buf, len);
			break;
		case ReqType_parseCert:
			ret = ParseCert_handle(fd, req, buf, len);
			break;
		case ReqType_validateCert:
			ret = ValidateCert_handle(fd, req, buf, len);
			break;
		case ReqType_signData:
			ret = SignData_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedData:
			ret = VerifySignedData_handle(fd, req, buf, len);
			break;
		case ReqType_signDataInit:
			ret = SignDataInit_handle(fd, req, buf, len);
			break;
		case ReqType_signDataUpdate:
			ret = SignDataUpdate_handle(fd, req, buf, len);
			break;
		case ReqType_signDataFinal:
			ret = SignDataFinal_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedDataInit:
			ret = VerifySignedDataInit_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedDataUpdate:
			ret = VerifySignedDataUpdate_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedDataFinal:
			ret = VerifySignedDataFinal_handle(fd, req, buf, len);
			break;
		case ReqType_signMessage:
	DEBUG("*len = %d\n", *len);
			ret = SignMessage_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedMessage:
			ret = VerifySignedMessage_handle(fd, req, buf, len);
			break;
		case ReqType_signMessageInit:
			ret = SignMessageInit_handle(fd, req, buf, len);
			break;
		case ReqType_signMessageUpdate:
			ret = SignMessageUpdate_handle(fd, req, buf, len);
			break;
		case ReqType_signMessageFinal:
			ret = SignMessageFinal_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedMessageInit:
			ret = VerifySignedMessageInit_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedMessageUpdate:
			ret = VerifySignedMessageUpdate_handle(fd, req, buf, len);
			break;
		case ReqType_verifySignedMessageFinal:
			ret = VerifySignedMessageFinal_handle(fd, req, buf, len);
			break;
		case ReqType_setCertTrustList:
			ret = SetCertTrustList_handle(fd, req, buf, len);
			break;
		case ReqType_getCertTrustListAltNames:
			ret = GetCertTrustListAltNames_handle(fd, req, buf, len);
			break;
		case ReqType_getCertTrustList:
			ret = GetCertTrustList_handle(fd, req, buf, len);
			break;
		case ReqType_delCertTrustList:
			ret = DelCertTrustList_handle(fd, req, buf, len);
			break;
		case ReqType_initCertAppPolicy:
			ret = InitCertAppPolicy_handle(fd, req, buf, len);
			break;
		case ReqType_getServerCertificate:
			ret = GetServerCertificate_handle(fd, req, buf, len);
			break;
		case ReqType_genRandom:
			ret = GenRandom_handle(fd, req, buf, len);
			break;
		case ReqType_getCertInfoByOid:
			ret = GetCertInfoByOid_handle(fd, req, buf, len);
			break;
		case ReqType_encryptData:
			ret = EncryptData_handle(fd, req, buf, len);
			break;
		case ReqType_decryptData:
			ret = DecryptData_handle(fd, req, buf, len);
			break;
		case ReqType_createTimeStampRequest:
			ret = CreateTimeStampRequest_handle(fd, req, buf, len);
			break;
		case ReqType_createTimeStampResponse:
			ret = CreateTimeStampResponse_handle(fd, req, buf, len);
			break;
		case ReqType_verifyTimeStamp:
			ret = VerifyTimeStamp_handle(fd, req, buf, len);
			break;
		case ReqType_getTimeStampInfo:
			ret = GetTimeStampInfo_handle(fd, req, buf, len);
			break;
		default:
        	DEBUG_Log("[%s|%s|%d]:Error: unknown request type:%d\n", __FILE__, __func__, __LINE__, req->reqType);
			break;
	}
	pthread_mutex_unlock(&g_lock__);
	DEBUG("ret = %08x, len = %d\n", ret, *len);

	return ret;
}
static void socket_cb(evutil_socket_t fd, short events, void *arg)
{
#define MAX_STACK_LEN 4096
	char buffer[5] = "";

	int inData_len = 0;
	char stack_buf[MAX_STACK_LEN] = "";
	char *recv_buf = stack_buf;
	char *heap_buf = NULL;

	char buf[MAX_STACK_LEN*2] ="";
	int len = sizeof(buf);
	char *out = buf;
	char *p = buf;
	char *heap_out = NULL;

	int ret = 0, tmp = -1, count = 0;
	struct event_base *base = (struct event_base *)arg;
	struct event *ev = event_base_get_running_event(base);
//	printf("current method = %s, feature = %02x\n", event_base_get_method(base), event_base_get_features(base));

	SVSRequest_t *req = NULL;
	asn_dec_rval_t dec_ret;
	DEBUG("*****************\n");

#ifdef _TIME_
	gettimeofday(&g_tv_begin, NULL);
#endif
	DEBUG("fd = %d, events = 0x%02x\n", fd, events);
	if ((events & EV_READ) && !(events & EV_CLOSED)) {
		ret = read(fd, buffer, sizeof(buffer));
		DEBUG("********first buffer fd = %d, ret = %d********\n", fd, ret);
#ifdef _DEBUG_
		int i=0;
		for (i=0; i<sizeof(buffer); i++)
			printf("%02X ", (unsigned char)buffer[i]);
		printf("\n");
#endif
		if (ret == 0) {
			DEBUG("***********Client CLOSED, so server closes the fd either************\n");
			goto _close;
		} else if (ret < 0) {
			/*note: Commmonly, for non-blocking socket, EAGAIN or EINTR are treated as correct case.
			  		But, as this server is based on libevent, so when read callback function is called, the socket must has data to read*/
			DEBUG("***********READ ERROR [%d|%s], it should not go to here************\n", errno, strerror(errno));
			DEBUG_Log("[%s|%s|%d]: Server read error ret = %d, strerror(errno)\n", __FILE__, __func__, __LINE__, ret, strerror(errno));
			goto _close;
		}
		inData_len = get_len_from_tag(buffer);
		//printf("inData_len = %d\n", inData_len);
		/* for large data */
		if (inData_len > MAX_STACK_LEN) {
			/* data in*/
			heap_buf = (char *)calloc(1, inData_len);
			if (!heap_buf)
				goto _close;
			recv_buf = heap_buf;
			/*data out*/
			heap_out = (char *)calloc(1, (int)(inData_len*2));
			if (!heap_out)
				goto _close;
			len = (int)(inData_len*2);
			out = heap_out;
			p = heap_out;
		}
		memcpy(recv_buf, buffer, sizeof(buffer));
		tmp = read(fd, recv_buf+ret, inData_len-ret);
		if (tmp > 0)
			ret += tmp;
		printf("--------ret = %d, inData_len = %d---------\n", ret, inData_len);
		while (ret < inData_len && count < INTERVAL_CNT) {
			usleep(100);
			count++;
			tmp = read(fd, recv_buf+ret, inData_len-ret);
			if (tmp > 0)
				ret += tmp;
			DEBUG("ret = %d, inData_len = %d\n", ret, inData_len);
		}
#ifdef _TIME_
		gettimeofday(&g_tv_end, NULL);
		printf("receive interval [%.6fs]\n", g_tv_end.tv_sec-g_tv_begin.tv_sec+(g_tv_end.tv_usec-g_tv_begin.tv_usec)*0.000001);
		total_time += (g_tv_end.tv_sec-g_tv_begin.tv_sec+(g_tv_end.tv_usec-g_tv_begin.tv_usec)*0.000001);
#endif
		if (ret != inData_len) {
			DEBUG("ret = %d, inData_len = %d\n", ret, inData_len);
			/* something must be wrong*/
			DEBUG_Log("[%s|%s|%d]: read error ret(%d)!= inData_len(%d)\n", __FILE__, __func__, __LINE__, ret, inData_len);
			goto _close;
		}
		/* Parse the client request */
		dec_ret = ber_decode(NULL, &asn_DEF_SVSRequest, (void **)&req, recv_buf, ret);
		if (dec_ret.code == RC_OK) {
			DEBUG("\n ----- decode successful-----\n");
			DEBUG(" -----version: %d-----\n", req->version);
			DEBUG(" -----reqType: %d-----\n", req->reqType);
			DEBUG("gmt: %s\n", req->reqTime.buf);

#ifdef _TIME_
			gettimeofday(&g_tv_begin, NULL);
#endif
			/* Handle the client request */
			DEBUG("len = %d\n", len);
			ret = svs_handle(fd, req, out, &len);
#ifdef _TIME_
			gettimeofday(&g_tv_end, NULL);
			printf("svs_handle interval [%.6fs]\n", g_tv_end.tv_sec-g_tv_begin.tv_sec+(g_tv_end.tv_usec-g_tv_begin.tv_usec)*0.000001);
			total_time += (g_tv_end.tv_sec-g_tv_begin.tv_sec+(g_tv_end.tv_usec-g_tv_begin.tv_usec)*0.000001);
			total_cnt++;
			printf("total_time = [%.6fs], speed = [%.6fs per handle]\n", total_time, total_time/total_cnt);
#endif
			DEBUG("svs_handle ret = %08x, len = %d\n", ret, len);

			if (len < 0) {
				DEBUG("\nfunction der_encode_to_buffer may be wrong!\n");
				DEBUG_Log("[%s|%s|%d]: function der_encode_to_buffer may be wrong, do 'der_encode_to_buffer' again!\n", __FILE__, __func__, __LINE__);
				len = MAX_STACK_LEN;
				p = buf;
				der_encode_error_case(req, p, &len);
				if (len < 0) {
					DEBUG("\nfunction der_encode_to_buffer may be wrong again!\n");
					DEBUG_Log("[%s|%s|%d]: function der_encode_to_buffer may be wrong again, close the socket!\n", __FILE__, __func__, __LINE__);
					goto _end;
				}
			}
			count=0;
			while (len > 0 && count < INTERVAL_CNT) {
				ret = write(fd, p, len);
				DEBUG("------write ret = %d------\n", ret);
				if (ret <= 0) {
					DEBUG("***********errno = %d************\n", errno);
					if(errno == EINTR || errno == EAGAIN) {
						usleep(1000);
						count++;
						continue;
					} else {
						DEBUG("***********WRITE ERROR, it should not go to here************\n");
						DEBUG_Log("[%s|%s|%d]: Server write error ret = %d, strerror(errno)\n", __FILE__, __func__, __LINE__, ret, strerror(errno));
						break;
					}
				}
				len -= ret;
				p += ret;
			}
			/*Don't close the socket fd without timeout.
			 * Just free the request struct data*/
				DEBUG("*******req = %p********\n", req);
			if (req) {
				free(req);
				req = NULL;
			}
			return;
		} else {
			DEBUG("\n ----- decode failed, Wrong Client Request!------\n");
			DEBUG_Log("[%s|%s|%d]: decode failed, Wrong Client Request!\n", __FILE__, __func__, __LINE__);
			goto _end;
		}
	} else if (events & EV_CLOSED || events & EV_TIMEOUT) {
		DEBUG("fd = %d, ev->ev_fd = %d\n", fd, ev->ev_fd);
		/* XXX a special case: the data and FIN arrive at the same time, it means the client close the socket and dont't need response any more.
			   so, just close the socket */
		goto _close;
	}
_end:
	if (req) {
		free(req);
		req = NULL;
	}
_close:
	if (ev->ev_fd)
		close(ev->ev_fd);
	event_free(ev);
	if (heap_buf) {
		free(heap_buf);
		heap_buf = NULL;
	}
	if (heap_out) {
		free(heap_out);
		heap_out = NULL;
	}
	return;
}
static void pipe_cb(evutil_socket_t fd, short event, void *arg)
{
	struct timeval tv;
	struct event *ev = NULL;
	char buf[1024];
	int pipe_bytes = 0;
	int new_fd=-1;
	int ret=-1;
	int i=0;
	int id = *(int *)arg;

	DEBUG("thread id = %d, event = 0x%02x, fd = %d\n", id, event, fd);
	if (event & EV_READ) {
		pipe_bytes = read(fd, buf, sizeof(buf));
		DEBUG("pipe read ret = %d\n", pipe_bytes);
		for (i=0; i<pipe_bytes; i++) {
			ret = de_queue(&g_thread[id].fd_queue, &new_fd);
			DEBUG("de_queue ret = %d, new_fd = %d\n", ret, new_fd);
			if (ret > 0) {
				DEBUG_Log("[%s|%s|%d]:Could not thread %d de_queue, maybe an empty queue!\n", __FILE__, __func__, __LINE__, id);
				return;
			}
			DEBUG("****************\n");
			ev = event_new(g_thread[id].base, new_fd, EV_READ|EV_PERSIST|EV_CLOSED, socket_cb, (void *)g_thread[id].base);
			evutil_timerclear(&tv);
			tv.tv_sec = 60;
			event_add(ev, &tv);
		}
	}
	return;
}
static void *thread_fun(void *arg)
{
	int id;
	struct event *ev;

	id = *(int *)arg;
	free(arg);
	pthread_detach(pthread_self());

	g_thread[id].base = event_base_new();
	if (!g_thread[id].base) {
		DEBUG_Log("[%s|%s|%d]:Could not initialize thread %d libevent!\n", __FILE__, __func__, __LINE__, id);
		return;
	}
	init_queue(&g_thread[id].fd_queue);
	pthread_mutex_init(&g_thread[id].lock, NULL);
	if (pipe(g_thread[id].fd) == 0) {
		//if (set_fl(g_thread[id].fd[0], O_NONBLOCK)<0 || set_fl(g_thread[id].fd[1], O_NONBLOCK)<0 || set_fd(g_thread[id].fd[0], FD_CLOEXEC)<0 || set_fd(g_thread[id].fd[1], FD_CLOEXEC)<0) {
		if (set_fd(g_thread[id].fd[0], FD_CLOEXEC)<0 || set_fd(g_thread[id].fd[1], FD_CLOEXEC)<0) {
			close(g_thread[id].fd[0]);
			close(g_thread[id].fd[1]);
			g_thread[id].fd[0] = g_thread[id].fd[1] = -1;
			DEBUG_Log("[%s|%s|%d]:Could not set thread %d pipe FD or FL!\n", __FILE__, __func__, __LINE__, id);
			return;
		}
		DEBUG("thread id = %d, fd[0] = %d, fd[1] = %d\n", id, g_thread[id].fd[0], g_thread[id].fd[1]);
	} else {
		DEBUG_Log("[%s|%s|%d]:Could not initialize thread %d pipe!\n", __FILE__, __func__, __LINE__, id);
		return;
	}
	ev = event_new(g_thread[id].base, g_thread[id].fd[0], EV_READ|EV_PERSIST, pipe_cb, (void *)&id);
	event_add(ev, NULL);
	//event_base_loop(g_thread[id].base, EVLOOP_NO_EXIT_ON_EMPTY);
	event_base_dispatch(g_thread[id].base);

	event_base_free(g_thread[id].base);
	printf("thread %d is exiting...\n", id);
}

static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
	int ret = -1;
	int id = -1;
next_thread:
	id = ++g_thread_index%NUM_OF_THREADS;
	DEBUG("thread id = %d\n", id);
	pthread_mutex_lock(&g_thread[id].lock);
	ret = en_queue(&g_thread[id].fd_queue, fd);
	if (ret > 0) {
		DEBUG_Log("[%s|%s|%d]:fd_queue of thread %d is full, try the next queue\n", __FILE__, __func__, __LINE__, id);
		pthread_mutex_unlock(&g_thread[id].lock);
		goto next_thread;
	}
	pthread_mutex_unlock(&g_thread[id].lock);
	ret = write(g_thread[id].fd[1], wake, strlen(wake));
	DEBUG("write ret = %d\n", ret);
}

int main(int argc, char **argv)
{
	struct evconnlistener *listener;
	struct event_base *base;

	int fd = 0;
	int i, *iptr;
	struct sockaddr_in sin;

//	evthread_use_pthreads();
	bzero(&g_thread, sizeof(g_thread));
	pthread_mutex_init(&g_log_lock, NULL);

	for (i=0; i<NUM_OF_THREADS; i++) {
		iptr = (int *)calloc(1, sizeof(int));
		*iptr = i;
		if (pthread_create(&g_thread[i].id, NULL, thread_fun, (void *)iptr) != 0) {
			DEBUG_Log("[%s|%s|%d]:Can't create [thread %d]\n", __FILE__, __func__, __LINE__, i);
			exit(1);
		}
	}

	base = event_base_new();
	if (!base) {
		DEBUG_Log("[%s|%s|%d]:Could not initialize libevent!\n", __FILE__, __func__, __LINE__);
		exit(2);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);

	fd = open("log.txt", O_RDWR|O_CREAT|O_APPEND, 0644);
	if (fd == -1) {
		DEBUG_Log("[%s|%s|%d]:Could not open the log file!\n", __FILE__, __func__, __LINE__);
		exit(3);
	}
	fflush(stderr);
	dup2(fd, STDERR_FILENO);

	listener = evconnlistener_new_bind(base, listener_cb, NULL,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
	    (struct sockaddr*)&sin,
	    sizeof(sin));

	if (!listener) {
		DEBUG_Log("[%s|%s|%d]:Could not create a listener!\n", __FILE__, __func__, __LINE__);
		exit(4);
	}
	if (open_ldap()) {
		DEBUG_Log("[%s|%s|%d]:Could not ldap_open()!\n", __FILE__, __func__, __LINE__);
		exit(5);
	}
	if(_init_cert_trust_list()>1) {
		DEBUG_Log("[%s|%s|%d]:Could not init Cert Trust List!\n", __FILE__, __func__, __LINE__);
		exit(6);
	}
#ifdef _TIME_
	signal(SIGUSR1, sig_usr);
#endif
	signal(SIGINT, sig_int);
	DEBUG_Log("[%s|%s|%d]:[Now the sign and verify server starts working!!!]\n", __FILE__, __func__, __LINE__);
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);
	close_ldap();

	printf("---server done---\n");
	exit(0);
}
