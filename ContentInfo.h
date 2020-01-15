/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "IBSVS"
 * 	found in "svs.asn"
 * 	`asn1c -fbless-SIZE`
 */

#ifndef	_ContentInfo_H_
#define	_ContentInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ContentType.h"
#include <ANY.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ContentInfo */
typedef struct ContentInfo {
	ContentType_t	 contentType;
	ANY_t	*content	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ContentInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ContentInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _ContentInfo_H_ */
#include <asn_internal.h>
