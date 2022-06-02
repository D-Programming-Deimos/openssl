/**
 * This file is a translation of `openssl/type.h`,
 * also known as `openssl/ossl_types.h` before v3.0.0.
 *
 * Copyright 2001-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
module deimos.openssl.types;

extern(C):
@system:
nothrow:

import deimos.openssl._d_util;

public import deimos.openssl.e_os2;

struct OSSL_PROVIDER; /* Provider Object */

version (NO_ASN1_TYPEDEFS) {
alias ASN1_STRING ASN1_INTEGER;
alias ASN1_STRING ASN1_ENUMERATED;
alias ASN1_STRING ASN1_BIT_STRING;
alias ASN1_STRING ASN1_OCTET_STRING;
alias ASN1_STRING ASN1_PRINTABLESTRING;
alias ASN1_STRING ASN1_T61STRING;
alias ASN1_STRING ASN1_IA5STRING;
alias ASN1_STRING ASN1_UTCTIME;
alias ASN1_STRING ASN1_GENERALIZEDTIME;
alias ASN1_STRING ASN1_TIME;
alias ASN1_STRING ASN1_GENERALSTRING;
alias ASN1_STRING ASN1_UNIVERSALSTRING;
alias ASN1_STRING ASN1_BMPSTRING;
alias ASN1_STRING ASN1_VISIBLESTRING;
alias ASN1_STRING ASN1_UTF8STRING;
alias int ASN1_BOOLEAN;
alias int ASN1_NULL;
} else {
import deimos.openssl.asn1;
alias asn1_string_st ASN1_INTEGER;
alias asn1_string_st ASN1_ENUMERATED;
alias asn1_string_st ASN1_BIT_STRING;
alias asn1_string_st ASN1_OCTET_STRING;
alias asn1_string_st ASN1_PRINTABLESTRING;
alias asn1_string_st ASN1_T61STRING;
alias asn1_string_st ASN1_IA5STRING;
alias asn1_string_st ASN1_GENERALSTRING;
alias asn1_string_st ASN1_UNIVERSALSTRING;
alias asn1_string_st ASN1_BMPSTRING;
alias asn1_string_st ASN1_UTCTIME;
alias asn1_string_st ASN1_TIME;
alias asn1_string_st ASN1_GENERALIZEDTIME;
alias asn1_string_st ASN1_VISIBLESTRING;
alias asn1_string_st ASN1_UTF8STRING;
alias asn1_string_st ASN1_STRING;
alias int ASN1_BOOLEAN;
alias int ASN1_NULL;
}

import deimos.openssl.asn1t;
alias ASN1_ITEM_st ASN1_ITEM;

struct asn1_pctx_st;
alias asn1_pctx_st ASN1_PCTX;

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
	struct BIGNUM;
	struct BN_CTX;
	struct BN_BLINDING;
	struct BN_MONT_CTX;
	struct BN_RECP_CTX;
	struct BN_GENCB;

	struct BUF_MEM;

	struct EVP_CIPHER;
	struct EVP_CIPHER_CTX;
	struct EVP_MD;
	struct EVP_MD_CTX;
	struct EVP_PKEY;

	struct EVP_KDF;
	struct EVP_KDF_CTX;

	// Backward compatible aliases, should not be used
	struct bignum_st;
	struct bn_mont_ctx_st;
	struct bn_recp_ctx_st;
	struct bn_gencb_st;
	struct buf_mem_st;
	struct env_md_ctx_st;
	struct evp_pkey_st;
	struct env_md_st;
	struct evp_cipher_st;
}
else
{
	struct bignum_st
	{
		BN_ULONG* d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
		int top;	/* Index of last used d +1. */
		/* The next are internal book keeping for bn_expand. */
		int dmax;	/* Size of the d array. */
		int neg;	/* one if the number is negative */
		int flags;
	}

	/* Used for montgomery multiplication */
	struct bn_mont_ctx_st
	{
		int ri;		   /* number of bits in R */
		BIGNUM RR;	   /* used to convert to montgomery form */
		BIGNUM N;	   /* The modulus */
		BIGNUM Ni;	   /* R*(1/R mod N) - N*Ni = 1
						   * (Ni is only stored for bignum algorithm) */
		BN_ULONG[2] n0;/* least significant word(s) of Ni;
						  (type changed with 0.9.9, was "BN_ULONG n0;" before) */
		int flags;
	}

	/* Used for reciprocal division/mod functions
	 * It cannot be shared between threads
	 */
	struct bn_recp_ctx_st
	{
		BIGNUM N;	/* the divisor */
		BIGNUM Nr;	/* the reciprocal */
		int num_bits;
		int shift;
		int flags;
	}

	/* Used for slow "generation" functions. */
	struct bn_gencb_st
	{
		uint ver;	/* To handle binary (in)compatibility */
		void* arg;		/* callback-specific data */
		union cb_
		{
			/* if(ver==1) - handles old style callbacks */
			ExternC!(void function(int, int, void*)) cb_1;
			/* if(ver==2) - new callback style */
			ExternC!(int function(int, int, BN_GENCB*)) cb_2;
		}
		cb_ cb;
	}

	alias BIGNUM = bignum_st;
	struct BN_CTX;
	struct BN_BLINDING;
	alias BN_MONT_CTX = bn_mont_ctx_st;
	alias BN_RECP_CTX = bn_recp_ctx_st;
	alias BN_GENCB = bn_gencb_st;

	struct buf_mem_st
	{
		size_t length;	/* current number of bytes */
		char* data;
		size_t max;	/* size of buffer */
	}

	alias BUF_MEM = buf_mem_st;


	struct env_md_ctx_st
	{
		const(EVP_MD)* digest;
		ENGINE* engine; /* functional reference if 'digest' is ENGINE-provided */
		c_ulong flags;
		void* md_data;
		/* Public key context for sign/verify */
		EVP_PKEY_CTX* pctx;
		/* Update function: usually copied from EVP_MD */
		ExternC!(int function(EVP_MD_CTX* ctx, const(void)* data, size_t count)) update;
	}

	/* Type needs to be a bit field
	 * Sub-type needs to be for variations on the method, as in_, can it do
	 * arbitrary encryption.... */
	struct evp_pkey_st
	{
		int type;
		int save_type;
		int references;
		const(EVP_PKEY_ASN1_METHOD)* ameth;
		ENGINE* engine;
		union pkey_ {
			char* ptr;
			version(OPENSSL_NO_RSA) {} else {
				RSA* rsa;	/* RSA */
			}
			version(OPENSSL_NO_DSA) {} else {
				dsa_st* dsa;	/* DSA */
			}
			version(OPENSSL_NO_DH) {} else {
				dh_st* dh;	/* DH */
			}
			version(OPENSSL_NO_EC) {} else {
				ec_key_st* ec;	/* ECC */
			}
		}
		pkey_ pkey;
		int save_parameters;
		STACK_OF!(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	}

	struct env_md_st
	{
		int type;
		int pkey_type;
		int md_size;
		c_ulong flags;
		ExternC!(int function(EVP_MD_CTX* ctx)) init_;
		ExternC!(int function(EVP_MD_CTX* ctx,const(void)* data,size_t count)) update;
		ExternC!(int function(EVP_MD_CTX* ctx,ubyte* md)) final_;
		ExternC!(int function(EVP_MD_CTX* to,const(EVP_MD_CTX)* from)) copy;
		ExternC!(int function(EVP_MD_CTX* ctx)) cleanup;

		/* FIXME: prototype these some day */
		ExternC!(int function(int type, const(ubyte)* m, uint m_length,
			ubyte* sigret, uint* siglen, void* key)) sign;
		ExternC!(int function(int type, const(ubyte)* m, uint m_length,
			  const(ubyte)* sigbuf, uint siglen,
			  void* key)) verify;
		int[5] required_pkey_type; /*EVP_PKEY_xxx */
		int block_size;
		int ctx_size; /* how big does the ctx->md_data need to be */
		/* control function */
		ExternC!(int function(EVP_MD_CTX* ctx, int cmd, int p1, void* p2)) md_ctrl;
	}

	struct evp_cipher_st
	{
		int nid;
		int block_size;
		int key_len;		/* Default value for variable length ciphers */
		int iv_len;
		c_ulong flags;	/* Various flags */
		ExternC!(int function(EVP_CIPHER_CTX* ctx, const(ubyte)* key,
			const(ubyte)* iv, int enc)) init_;	/* init key */
		ExternC!(int function(EVP_CIPHER_CTX* ctx, ubyte* out_,
			 const(ubyte)* in_, size_t inl)) do_cipher;/* encrypt/decrypt data */
		ExternC!(int function(EVP_CIPHER_CTX*)) cleanup; /* cleanup ctx */
		int ctx_size;		/* how big ctx->cipher_data needs to be */
		ExternC!(int function(EVP_CIPHER_CTX*, ASN1_TYPE*)) set_asn1_parameters; /* Populate a ASN1_TYPE with parameters */
		ExternC!(int function(EVP_CIPHER_CTX*, ASN1_TYPE*)) get_asn1_parameters; /* Get parameters from a ASN1_TYPE */
		ExternC!(int function(EVP_CIPHER_CTX*, int type, int arg, void* ptr)) ctrl; /* Miscellaneous operations */
		void* app_data;		/* Application data */
	}

	alias EVP_MD = env_md_st;
	alias EVP_MD_CTX = env_md_ctx_st;
	alias EVP_CIPHER = evp_cipher_st;
	alias EVP_CIPHER_CTX = evp_cipher_ctx_st;

	alias EVP_PKEY = evp_pkey_st;
}

struct evp_pkey_asn1_method_st;
alias evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
struct evp_pkey_method_st;
alias evp_pkey_method_st EVP_PKEY_METHOD;
struct evp_pkey_ctx_st;
alias evp_pkey_ctx_st EVP_PKEY_CTX;


import deimos.openssl.dh;
/*struct dh_st;*/
alias dh_st DH;
/*struct dh_method;*/
alias dh_method DH_METHOD;

import deimos.openssl.dsa;
/*struct dsa_st;*/
alias dsa_st DSA;
/*struct dsa_method;*/
alias dsa_method DSA_METHOD;

import deimos.openssl.rsa;
private struct rsa_st;
alias rsa_st RSA;
private struct rsa_meth_st;
alias rsa_meth_st RSA_METHOD;

import deimos.openssl.rand;
alias rand_meth_st RAND_METHOD;

struct ecdh_method;
alias ecdh_method ECDH_METHOD;
struct ecdsa_method;
alias ecdsa_method ECDSA_METHOD;

import deimos.openssl.x509;
import deimos.openssl.x509_vfy;

struct ssl_dane_st;
alias SSL_DANE = ssl_dane_st;

struct x509_st;
alias x509_st X509;
alias X509_algor_st X509_ALGOR;
struct X509_crl_st;
alias X509_crl_st X509_CRL;
struct x509_crl_method_st;
alias x509_crl_method_st X509_CRL_METHOD;
struct x509_revoked_st;
alias x509_revoked_st X509_REVOKED;
struct X509_name_st;
alias X509_name_st X509_NAME;
struct X509_pubkey_st;
alias X509_pubkey_st X509_PUBKEY;
struct x509_store_st;
alias x509_store_st X509_STORE;
struct x509_store_ctx_st;
alias x509_store_ctx_st X509_STORE_CTX;
struct x509_lookup_st;
alias X509_LOOKUP = x509_lookup_st;

struct x509_object_st;
alias X509_OBJECT = x509_object_st;
struct x509_lookup_method_st;
alias X509_LOOKUP_METHOD = x509_lookup_method_st;
struct X509_VERIFY_PARAM_st;
alias X509_VERIFY_PARAM = X509_VERIFY_PARAM_st;

struct pkcs8_priv_key_info_st;
alias pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;

import deimos.openssl.x509v3;
alias v3_ext_ctx X509V3_CTX;
import deimos.openssl.conf;
alias conf_st CONF;

struct store_st;
alias store_st STORE;
struct store_method_st;
alias store_method_st STORE_METHOD;

struct ui_st;
alias ui_st UI;
struct ui_method_st;
alias ui_method_st UI_METHOD;

struct st_ERR_FNS;
alias st_ERR_FNS ERR_FNS;

struct engine_st;
alias engine_st ENGINE;

struct X509_POLICY_NODE_st;
alias X509_POLICY_NODE_st X509_POLICY_NODE;
struct X509_POLICY_LEVEL_st;
alias X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
struct X509_POLICY_TREE_st;
alias X509_POLICY_TREE_st X509_POLICY_TREE;
struct X509_POLICY_CACHE_st;
alias X509_POLICY_CACHE_st X509_POLICY_CACHE;

alias AUTHORITY_KEYID_st AUTHORITY_KEYID;
alias DIST_POINT_st DIST_POINT;
alias ISSUING_DIST_POINT_st ISSUING_DIST_POINT;
alias NAME_CONSTRAINTS_st NAME_CONSTRAINTS;

  /* If placed in pkcs12.h, we end up with a circular depency with pkcs7.h */
mixin template DECLARE_PKCS12_STACK_OF (type) { /* Nothing */ }
//#define IMPLEMENT_PKCS12_STACK_OF!(type) /* Nothing */

import deimos.openssl.crypto;
alias crypto_ex_data_st CRYPTO_EX_DATA;
/* Callback types for crypto.h */
alias typeof(*(ExternC!(int function(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
					int idx, c_long argl, void* argp))).init) CRYPTO_EX_new;
alias typeof(*(ExternC!(void function(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
					int idx, c_long argl, void* argp))).init) CRYPTO_EX_free;
alias typeof(*(ExternC!(int function(CRYPTO_EX_DATA* to, CRYPTO_EX_DATA* from, void* from_d,
					int idx, c_long argl, void* argp))).init) CRYPTO_EX_dup;

import deimos.openssl.ocsp;
struct ocsp_req_ctx_st;
alias ocsp_req_ctx_st OCSP_REQ_CTX;
/*struct ocsp_response_st;*/
alias ocsp_response_st OCSP_RESPONSE;
/*struct ocsp_responder_id_st;*/
alias ocsp_responder_id_st OCSP_RESPID;

struct OSSL_LIB_CTX;

struct OSSL_PARAM;
