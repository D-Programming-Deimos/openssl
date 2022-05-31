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

//#ifdef OPENSSL_SYS_WIN32
//#undef X509_NAME
//#undef X509_EXTENSIONS
//#undef X509_CERT_PAIR
//#undef PKCS7_ISSUER_AND_SERIAL
//#undef OCSP_REQUEST
//#undef OCSP_RESPONSE
//#endif

//#ifdef BIGNUM
//#undef BIGNUM
//#endif
import deimos.openssl.bn;
alias bignum_st BIGNUM;
struct bignum_ctx;
alias bignum_ctx BN_CTX;
struct bn_blinding_st;
alias bn_blinding_st BN_BLINDING;
alias bn_mont_ctx_st BN_MONT_CTX;
alias bn_recp_ctx_st BN_RECP_CTX;
alias bn_gencb_st BN_GENCB;

import deimos.openssl.buffer;
alias buf_mem_st BUF_MEM;

import deimos.openssl.evp;
alias evp_cipher_st EVP_CIPHER;
alias evp_cipher_ctx_st EVP_CIPHER_CTX;
alias env_md_st EVP_MD;
alias env_md_ctx_st EVP_MD_CTX;
alias evp_pkey_st EVP_PKEY;

struct evp_pkey_asn1_method_st;
alias evp_pkey_asn1_method_st EVP_PKEY_ASN1_METHOD;
struct evp_pkey_method_st;
alias evp_pkey_method_st EVP_PKEY_METHOD;
struct evp_pkey_ctx_st;
alias evp_pkey_ctx_st EVP_PKEY_CTX;

struct EVP_KDF;
struct EVP_KDF_CTX;

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
