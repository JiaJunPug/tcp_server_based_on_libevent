/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "IBSVS"
 * 	found in "svs.asn"
 * 	`asn1c -fbless-SIZE`
 */

#ifndef	_Attributes_H_
#define	_Attributes_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SET_OF.h>
#include <constr_SET_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Attribute;

/* Attributes */
typedef struct Attributes {
	A_SET_OF(struct Attribute) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Attributes_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Attributes;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Attribute.h"

#endif	/* _Attributes_H_ */
#include <asn_internal.h>