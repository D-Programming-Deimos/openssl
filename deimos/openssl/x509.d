/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

module deimos.openssl.x509;

import core.stdc.time;

import deimos.openssl._d_util;
import deimos.openssl.x509v3 : stack_st_ASN1_OBJECT;

public import deimos.openssl.e_os2;
public import deimos.openssl.ossl_typ;
public import deimos.openssl.symhacks;
public import deimos.openssl.buffer;
public import deimos.openssl.evp;
public import deimos.openssl.bio;
public import deimos.openssl.stack;
public import deimos.openssl.asn1;
public import deimos.openssl.safestack;
public import deimos.openssl.ec;

/* if OPENSSL_API_COMPAT < 0x10100000L */
public import deimos.openssl.rsa;
public import deimos.openssl.dsa;
public import deimos.openssl.dh;
/* endif */

public import deimos.openssl.sha;

extern (C):
nothrow:

enum X509_FILETYPE_PEM = 1;
enum X509_FILETYPE_ASN1 = 2;
enum X509_FILETYPE_DEFAULT = 3;

enum X509v3_KU_DIGITAL_SIGNATURE = 0x0080;
enum X509v3_KU_NON_REPUDIATION = 0x0040;
enum X509v3_KU_KEY_ENCIPHERMENT = 0x0020;
enum X509v3_KU_DATA_ENCIPHERMENT = 0x0010;
enum X509v3_KU_KEY_AGREEMENT = 0x0008;
enum X509v3_KU_KEY_CERT_SIGN = 0x0004;
enum X509v3_KU_CRL_SIGN = 0x0002;
enum X509v3_KU_ENCIPHER_ONLY = 0x0001;
enum X509v3_KU_DECIPHER_ONLY = 0x8000;
enum X509v3_KU_UNDEF = 0xffff;

struct X509_algor_st
{
    ASN1_OBJECT* algorithm;
    ASN1_TYPE* parameter;
} /* X509_ALGOR */

/* This is used for a table of trust checking functions */

/* standard trust ids */

/* Only valid in purpose settings */

/* Keep these up to date! */

/* trust_flags values */

/* No compat trust if self-signed, preempts "DO_SS" */

/* Compat trust if no explicit accepted trust EKUs */

/* Accept "anyEKU" as a wildcard trust OID */

/* check_trust return codes */

/* Flags for X509_print_ex() */
struct stack_st_X509_ALGOR;
alias X509_ALGORS = stack_st_X509_ALGOR;

struct X509_val_st
{
    ASN1_TIME* notBefore;
    ASN1_TIME* notAfter;
}

alias X509_VAL = X509_val_st;
struct X509_sig_st;
alias X509_SIG = X509_sig_st;
struct X509_name_entry_st;
alias X509_NAME_ENTRY = X509_name_entry_st;
struct stack_st_X509_NAME_ENTRY;
alias sk_X509_NAME_ENTRY_compfunc = int function(const(X509_NAME_ENTRY*)* a, const(X509_NAME_ENTRY*)* b);
alias sk_X509_NAME_ENTRY_freefunc = void function(X509_NAME_ENTRY* a);
alias sk_X509_NAME_ENTRY_copyfunc = X509_name_entry_st* function(const(X509_NAME_ENTRY)* a);
int sk_X509_NAME_ENTRY_num(const(stack_st_X509_NAME_ENTRY)* sk);
X509_NAME_ENTRY* sk_X509_NAME_ENTRY_value(const(stack_st_X509_NAME_ENTRY)* sk, int idx);
stack_st_X509_NAME_ENTRY* sk_X509_NAME_ENTRY_new(sk_X509_NAME_ENTRY_compfunc compare);
stack_st_X509_NAME_ENTRY* sk_X509_NAME_ENTRY_new_null();
void sk_X509_NAME_ENTRY_free(stack_st_X509_NAME_ENTRY* sk);
void sk_X509_NAME_ENTRY_zero(stack_st_X509_NAME_ENTRY* sk);
X509_NAME_ENTRY* sk_X509_NAME_ENTRY_delete(stack_st_X509_NAME_ENTRY* sk, int i);
X509_NAME_ENTRY* sk_X509_NAME_ENTRY_delete_ptr(stack_st_X509_NAME_ENTRY* sk, X509_NAME_ENTRY* ptr);
int sk_X509_NAME_ENTRY_push(stack_st_X509_NAME_ENTRY* sk, X509_NAME_ENTRY* ptr);
int sk_X509_NAME_ENTRY_unshift(stack_st_X509_NAME_ENTRY* sk, X509_NAME_ENTRY* ptr);
X509_NAME_ENTRY* sk_X509_NAME_ENTRY_pop(stack_st_X509_NAME_ENTRY* sk);
X509_NAME_ENTRY* sk_X509_NAME_ENTRY_shift(stack_st_X509_NAME_ENTRY* sk);
void sk_X509_NAME_ENTRY_pop_free(stack_st_X509_NAME_ENTRY* sk, sk_X509_NAME_ENTRY_freefunc freefunc);
int sk_X509_NAME_ENTRY_insert(stack_st_X509_NAME_ENTRY* sk, X509_NAME_ENTRY* ptr, int idx);
X509_NAME_ENTRY* sk_X509_NAME_ENTRY_set(stack_st_X509_NAME_ENTRY* sk, int idx, X509_NAME_ENTRY* ptr);
int sk_X509_NAME_ENTRY_find(stack_st_X509_NAME_ENTRY* sk, X509_NAME_ENTRY* ptr);
int sk_X509_NAME_ENTRY_find_ex(stack_st_X509_NAME_ENTRY* sk, X509_NAME_ENTRY* ptr);
void sk_X509_NAME_ENTRY_sort(stack_st_X509_NAME_ENTRY* sk);
int sk_X509_NAME_ENTRY_is_sorted(const(stack_st_X509_NAME_ENTRY)* sk);
stack_st_X509_NAME_ENTRY* sk_X509_NAME_ENTRY_dup(const(stack_st_X509_NAME_ENTRY)* sk);
stack_st_X509_NAME_ENTRY* sk_X509_NAME_ENTRY_deep_copy(const(stack_st_X509_NAME_ENTRY)* sk, sk_X509_NAME_ENTRY_copyfunc copyfunc, sk_X509_NAME_ENTRY_freefunc freefunc);
sk_X509_NAME_ENTRY_compfunc sk_X509_NAME_ENTRY_set_cmp_func(stack_st_X509_NAME_ENTRY* sk, sk_X509_NAME_ENTRY_compfunc compare);
struct stack_st_X509_NAME;
alias sk_X509_NAME_compfunc = int function(const(X509_NAME*)* a, const(X509_NAME*)* b);
alias sk_X509_NAME_freefunc = void function(X509_NAME* a);
alias sk_X509_NAME_copyfunc = X509_name_st* function(const(X509_NAME)* a);
int sk_X509_NAME_num(const(stack_st_X509_NAME)* sk);
X509_NAME* sk_X509_NAME_value(const(stack_st_X509_NAME)* sk, int idx);
stack_st_X509_NAME* sk_X509_NAME_new(sk_X509_NAME_compfunc compare);
stack_st_X509_NAME* sk_X509_NAME_new_null();
void sk_X509_NAME_free(stack_st_X509_NAME* sk);
void sk_X509_NAME_zero(stack_st_X509_NAME* sk);
X509_NAME* sk_X509_NAME_delete(stack_st_X509_NAME* sk, int i);
X509_NAME* sk_X509_NAME_delete_ptr(stack_st_X509_NAME* sk, X509_NAME* ptr);
int sk_X509_NAME_push(stack_st_X509_NAME* sk, X509_NAME* ptr);
int sk_X509_NAME_unshift(stack_st_X509_NAME* sk, X509_NAME* ptr);
X509_NAME* sk_X509_NAME_pop(stack_st_X509_NAME* sk);
X509_NAME* sk_X509_NAME_shift(stack_st_X509_NAME* sk);
void sk_X509_NAME_pop_free(stack_st_X509_NAME* sk, sk_X509_NAME_freefunc freefunc);
int sk_X509_NAME_insert(stack_st_X509_NAME* sk, X509_NAME* ptr, int idx);
X509_NAME* sk_X509_NAME_set(stack_st_X509_NAME* sk, int idx, X509_NAME* ptr);
int sk_X509_NAME_find(stack_st_X509_NAME* sk, X509_NAME* ptr);
int sk_X509_NAME_find_ex(stack_st_X509_NAME* sk, X509_NAME* ptr);
void sk_X509_NAME_sort(stack_st_X509_NAME* sk);
int sk_X509_NAME_is_sorted(const(stack_st_X509_NAME)* sk);
stack_st_X509_NAME* sk_X509_NAME_dup(const(stack_st_X509_NAME)* sk);
stack_st_X509_NAME* sk_X509_NAME_deep_copy(const(stack_st_X509_NAME)* sk, sk_X509_NAME_copyfunc copyfunc, sk_X509_NAME_freefunc freefunc);
sk_X509_NAME_compfunc sk_X509_NAME_set_cmp_func(stack_st_X509_NAME* sk, sk_X509_NAME_compfunc compare);
enum X509_EX_V_NETSCAPE_HACK = 0x8000;
enum X509_EX_V_INIT = 0x0001;
struct X509_extension_st;
alias X509_EXTENSION = X509_extension_st;
struct stack_st_X509_EXTENSION;
alias X509_EXTENSIONS = stack_st_X509_EXTENSION;
alias sk_X509_EXTENSION_compfunc = int function(const(X509_EXTENSION*)* a, const(X509_EXTENSION*)* b);
alias sk_X509_EXTENSION_freefunc = void function(X509_EXTENSION* a);
alias sk_X509_EXTENSION_copyfunc = X509_extension_st* function(const(X509_EXTENSION)* a);
int sk_X509_EXTENSION_num(const(stack_st_X509_EXTENSION)* sk);
X509_EXTENSION* sk_X509_EXTENSION_value(const(stack_st_X509_EXTENSION)* sk, int idx);
stack_st_X509_EXTENSION* sk_X509_EXTENSION_new(sk_X509_EXTENSION_compfunc compare);
stack_st_X509_EXTENSION* sk_X509_EXTENSION_new_null();
void sk_X509_EXTENSION_free(stack_st_X509_EXTENSION* sk);
void sk_X509_EXTENSION_zero(stack_st_X509_EXTENSION* sk);
X509_EXTENSION* sk_X509_EXTENSION_delete(stack_st_X509_EXTENSION* sk, int i);
X509_EXTENSION* sk_X509_EXTENSION_delete_ptr(stack_st_X509_EXTENSION* sk, X509_EXTENSION* ptr);
int sk_X509_EXTENSION_push(stack_st_X509_EXTENSION* sk, X509_EXTENSION* ptr);
int sk_X509_EXTENSION_unshift(stack_st_X509_EXTENSION* sk, X509_EXTENSION* ptr);
X509_EXTENSION* sk_X509_EXTENSION_pop(stack_st_X509_EXTENSION* sk);
X509_EXTENSION* sk_X509_EXTENSION_shift(stack_st_X509_EXTENSION* sk);
void sk_X509_EXTENSION_pop_free(stack_st_X509_EXTENSION* sk, sk_X509_EXTENSION_freefunc freefunc);
int sk_X509_EXTENSION_insert(stack_st_X509_EXTENSION* sk, X509_EXTENSION* ptr, int idx);
X509_EXTENSION* sk_X509_EXTENSION_set(stack_st_X509_EXTENSION* sk, int idx, X509_EXTENSION* ptr);
int sk_X509_EXTENSION_find(stack_st_X509_EXTENSION* sk, X509_EXTENSION* ptr);
int sk_X509_EXTENSION_find_ex(stack_st_X509_EXTENSION* sk, X509_EXTENSION* ptr);
void sk_X509_EXTENSION_sort(stack_st_X509_EXTENSION* sk);
int sk_X509_EXTENSION_is_sorted(const(stack_st_X509_EXTENSION)* sk);
stack_st_X509_EXTENSION* sk_X509_EXTENSION_dup(const(stack_st_X509_EXTENSION)* sk);
stack_st_X509_EXTENSION* sk_X509_EXTENSION_deep_copy(const(stack_st_X509_EXTENSION)* sk, sk_X509_EXTENSION_copyfunc copyfunc, sk_X509_EXTENSION_freefunc freefunc);
sk_X509_EXTENSION_compfunc sk_X509_EXTENSION_set_cmp_func(stack_st_X509_EXTENSION* sk, sk_X509_EXTENSION_compfunc compare);
struct x509_attributes_st;
alias X509_ATTRIBUTE = x509_attributes_st;
struct stack_st_X509_ATTRIBUTE;
alias sk_X509_ATTRIBUTE_compfunc = int function(const(X509_ATTRIBUTE*)* a, const(X509_ATTRIBUTE*)* b);
alias sk_X509_ATTRIBUTE_freefunc = void function(X509_ATTRIBUTE* a);
alias sk_X509_ATTRIBUTE_copyfunc = x509_attributes_st* function(const(X509_ATTRIBUTE)* a);
int sk_X509_ATTRIBUTE_num(const(stack_st_X509_ATTRIBUTE)* sk);
X509_ATTRIBUTE* sk_X509_ATTRIBUTE_value(const(stack_st_X509_ATTRIBUTE)* sk, int idx);
stack_st_X509_ATTRIBUTE* sk_X509_ATTRIBUTE_new(sk_X509_ATTRIBUTE_compfunc compare);
stack_st_X509_ATTRIBUTE* sk_X509_ATTRIBUTE_new_null();
void sk_X509_ATTRIBUTE_free(stack_st_X509_ATTRIBUTE* sk);
void sk_X509_ATTRIBUTE_zero(stack_st_X509_ATTRIBUTE* sk);
X509_ATTRIBUTE* sk_X509_ATTRIBUTE_delete(stack_st_X509_ATTRIBUTE* sk, int i);
X509_ATTRIBUTE* sk_X509_ATTRIBUTE_delete_ptr(stack_st_X509_ATTRIBUTE* sk, X509_ATTRIBUTE* ptr);
int sk_X509_ATTRIBUTE_push(stack_st_X509_ATTRIBUTE* sk, X509_ATTRIBUTE* ptr);
int sk_X509_ATTRIBUTE_unshift(stack_st_X509_ATTRIBUTE* sk, X509_ATTRIBUTE* ptr);
X509_ATTRIBUTE* sk_X509_ATTRIBUTE_pop(stack_st_X509_ATTRIBUTE* sk);
X509_ATTRIBUTE* sk_X509_ATTRIBUTE_shift(stack_st_X509_ATTRIBUTE* sk);
void sk_X509_ATTRIBUTE_pop_free(stack_st_X509_ATTRIBUTE* sk, sk_X509_ATTRIBUTE_freefunc freefunc);
int sk_X509_ATTRIBUTE_insert(stack_st_X509_ATTRIBUTE* sk, X509_ATTRIBUTE* ptr, int idx);
X509_ATTRIBUTE* sk_X509_ATTRIBUTE_set(stack_st_X509_ATTRIBUTE* sk, int idx, X509_ATTRIBUTE* ptr);
int sk_X509_ATTRIBUTE_find(stack_st_X509_ATTRIBUTE* sk, X509_ATTRIBUTE* ptr);
int sk_X509_ATTRIBUTE_find_ex(stack_st_X509_ATTRIBUTE* sk, X509_ATTRIBUTE* ptr);
void sk_X509_ATTRIBUTE_sort(stack_st_X509_ATTRIBUTE* sk);
int sk_X509_ATTRIBUTE_is_sorted(const(stack_st_X509_ATTRIBUTE)* sk);
stack_st_X509_ATTRIBUTE* sk_X509_ATTRIBUTE_dup(const(stack_st_X509_ATTRIBUTE)* sk);
stack_st_X509_ATTRIBUTE* sk_X509_ATTRIBUTE_deep_copy(const(stack_st_X509_ATTRIBUTE)* sk, sk_X509_ATTRIBUTE_copyfunc copyfunc, sk_X509_ATTRIBUTE_freefunc freefunc);
sk_X509_ATTRIBUTE_compfunc sk_X509_ATTRIBUTE_set_cmp_func(stack_st_X509_ATTRIBUTE* sk, sk_X509_ATTRIBUTE_compfunc compare);
struct X509_req_info_st;
alias X509_REQ_INFO = X509_req_info_st;
struct X509_req_st;
alias X509_REQ = X509_req_st;
struct x509_cert_aux_st;
alias X509_CERT_AUX = x509_cert_aux_st;
struct x509_cinf_st;
alias X509_CINF = x509_cinf_st;
struct stack_st_X509;
alias sk_X509_compfunc = int function(const(X509*)* a, const(X509*)* b);
alias sk_X509_freefunc = void function(X509* a);
alias sk_X509_copyfunc = x509_st* function(const(X509)* a);
int sk_X509_num(const(stack_st_X509)* sk);
X509* sk_X509_value(const(stack_st_X509)* sk, int idx);
stack_st_X509* sk_X509_new(sk_X509_compfunc compare);
stack_st_X509* sk_X509_new_null();
void sk_X509_free(stack_st_X509* sk);
void sk_X509_zero(stack_st_X509* sk);
X509* sk_X509_delete(stack_st_X509* sk, int i);
X509* sk_X509_delete_ptr(stack_st_X509* sk, X509* ptr);
int sk_X509_push(stack_st_X509* sk, X509* ptr);
int sk_X509_unshift(stack_st_X509* sk, X509* ptr);
X509* sk_X509_pop(stack_st_X509* sk);
X509* sk_X509_shift(stack_st_X509* sk);
void sk_X509_pop_free(stack_st_X509* sk, sk_X509_freefunc freefunc);
int sk_X509_insert(stack_st_X509* sk, X509* ptr, int idx);
X509* sk_X509_set(stack_st_X509* sk, int idx, X509* ptr);
int sk_X509_find(stack_st_X509* sk, X509* ptr);
int sk_X509_find_ex(stack_st_X509* sk, X509* ptr);
void sk_X509_sort(stack_st_X509* sk);
int sk_X509_is_sorted(const(stack_st_X509)* sk);
stack_st_X509* sk_X509_dup(const(stack_st_X509)* sk);
stack_st_X509* sk_X509_deep_copy(const(stack_st_X509)* sk, sk_X509_copyfunc copyfunc, sk_X509_freefunc freefunc);
sk_X509_compfunc sk_X509_set_cmp_func(stack_st_X509* sk, sk_X509_compfunc compare);

struct x509_trust_st
{
    int trust;
    int flags;
    int function(x509_trust_st*, X509*, int) check_trust;
    char* name;
    int arg1;
    void* arg2;
}

alias X509_TRUST = x509_trust_st;
struct stack_st_X509_TRUST;
alias sk_X509_TRUST_compfunc = int function(const(X509_TRUST*)* a, const(X509_TRUST*)* b);
alias sk_X509_TRUST_freefunc = void function(X509_TRUST* a);
alias sk_X509_TRUST_copyfunc = x509_trust_st* function(const(X509_TRUST)* a);
int sk_X509_TRUST_num(const(stack_st_X509_TRUST)* sk);
X509_TRUST* sk_X509_TRUST_value(const(stack_st_X509_TRUST)* sk, int idx);
stack_st_X509_TRUST* sk_X509_TRUST_new(sk_X509_TRUST_compfunc compare);
stack_st_X509_TRUST* sk_X509_TRUST_new_null();
void sk_X509_TRUST_free(stack_st_X509_TRUST* sk);
void sk_X509_TRUST_zero(stack_st_X509_TRUST* sk);
X509_TRUST* sk_X509_TRUST_delete(stack_st_X509_TRUST* sk, int i);
X509_TRUST* sk_X509_TRUST_delete_ptr(stack_st_X509_TRUST* sk, X509_TRUST* ptr);
int sk_X509_TRUST_push(stack_st_X509_TRUST* sk, X509_TRUST* ptr);
int sk_X509_TRUST_unshift(stack_st_X509_TRUST* sk, X509_TRUST* ptr);
X509_TRUST* sk_X509_TRUST_pop(stack_st_X509_TRUST* sk);
X509_TRUST* sk_X509_TRUST_shift(stack_st_X509_TRUST* sk);
void sk_X509_TRUST_pop_free(stack_st_X509_TRUST* sk, sk_X509_TRUST_freefunc freefunc);
int sk_X509_TRUST_insert(stack_st_X509_TRUST* sk, X509_TRUST* ptr, int idx);
X509_TRUST* sk_X509_TRUST_set(stack_st_X509_TRUST* sk, int idx, X509_TRUST* ptr);
int sk_X509_TRUST_find(stack_st_X509_TRUST* sk, X509_TRUST* ptr);
int sk_X509_TRUST_find_ex(stack_st_X509_TRUST* sk, X509_TRUST* ptr);
void sk_X509_TRUST_sort(stack_st_X509_TRUST* sk);
int sk_X509_TRUST_is_sorted(const(stack_st_X509_TRUST)* sk);
stack_st_X509_TRUST* sk_X509_TRUST_dup(const(stack_st_X509_TRUST)* sk);
stack_st_X509_TRUST* sk_X509_TRUST_deep_copy(const(stack_st_X509_TRUST)* sk, sk_X509_TRUST_copyfunc copyfunc, sk_X509_TRUST_freefunc freefunc);
sk_X509_TRUST_compfunc sk_X509_TRUST_set_cmp_func(stack_st_X509_TRUST* sk, sk_X509_TRUST_compfunc compare);
enum X509_TRUST_DEFAULT = 0;
enum X509_TRUST_COMPAT = 1;
enum X509_TRUST_SSL_CLIENT = 2;
enum X509_TRUST_SSL_SERVER = 3;
enum X509_TRUST_EMAIL = 4;
enum X509_TRUST_OBJECT_SIGN = 5;
enum X509_TRUST_OCSP_SIGN = 6;
enum X509_TRUST_OCSP_REQUEST = 7;
enum X509_TRUST_TSA = 8;
enum X509_TRUST_MIN = 1;
enum X509_TRUST_MAX = 8;
enum X509_TRUST_DYNAMIC = 1U << 0;
enum X509_TRUST_DYNAMIC_NAME = 1U << 1;
enum X509_TRUST_NO_SS_COMPAT = 1U << 2;
enum X509_TRUST_DO_SS_COMPAT = 1U << 3;
enum X509_TRUST_OK_ANY_EKU = 1U << 4;
enum X509_TRUST_TRUSTED = 1;
enum X509_TRUST_REJECTED = 2;
enum X509_TRUST_UNTRUSTED = 3;

enum X509_FLAG_COMPAT = 0;
enum X509_FLAG_NO_HEADER = 1L;
enum X509_FLAG_NO_VERSION = 1L << 1;
enum X509_FLAG_NO_SERIAL = 1L << 2;
enum X509_FLAG_NO_SIGNAME = 1L << 3;
enum X509_FLAG_NO_ISSUER = 1L << 4;
enum X509_FLAG_NO_VALIDITY = 1L << 5;
enum X509_FLAG_NO_SUBJECT = 1L << 6;
enum X509_FLAG_NO_PUBKEY = 1L << 7;
enum X509_FLAG_NO_EXTENSIONS = 1L << 8;
enum X509_FLAG_NO_SIGDUMP = 1L << 9;
enum X509_FLAG_NO_AUX = 1L << 10;
enum X509_FLAG_NO_ATTRIBUTES = 1L << 11;
enum X509_FLAG_NO_IDS = 1L << 12;

/* Flags specific to X509_NAME_print_ex() */

/* The field separator information */

enum XN_FLAG_SEP_MASK = 0xf << 16;

enum XN_FLAG_COMPAT = 0; /* Traditional; use old X509_NAME_print */
enum XN_FLAG_SEP_COMMA_PLUS = 1 << 16; /* RFC2253 ,+ */
enum XN_FLAG_SEP_CPLUS_SPC = 2 << 16; /* ,+ spaced: more readable */
enum XN_FLAG_SEP_SPLUS_SPC = 3 << 16; /* ;+ spaced */
enum XN_FLAG_SEP_MULTILINE = 4 << 16; /* One line per field */

enum XN_FLAG_DN_REV = 1 << 20; /* Reverse DN order */

/* How the field name is shown */

enum XN_FLAG_FN_MASK = 0x3 << 21;

enum XN_FLAG_FN_SN = 0; /* Object short name */
enum XN_FLAG_FN_LN = 1 << 21; /* Object long name */
enum XN_FLAG_FN_OID = 2 << 21; /* Always use OIDs */
enum XN_FLAG_FN_NONE = 3 << 21; /* No field names */

enum XN_FLAG_SPC_EQ = 1 << 23; /* Put spaces round '=' */

/*
 * This determines if we dump fields we don't recognise: RFC2253 requires
 * this.
 */

enum XN_FLAG_DUMP_UNKNOWN_FIELDS = 1 << 24;

enum XN_FLAG_FN_ALIGN = 1 << 25; /* Align field names to 20
 * characters */

/* Complete set of RFC2253 flags */

enum XN_FLAG_RFC2253 = ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_DN_REV | XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS;

/* readable oneline form */

enum XN_FLAG_ONELINE = ASN1_STRFLGS_RFC2253 | ASN1_STRFLGS_ESC_QUOTE | XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_SPC_EQ | XN_FLAG_FN_SN;

/* readable multiline form */

enum XN_FLAG_MULTILINE = ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB | XN_FLAG_SEP_MULTILINE | XN_FLAG_SPC_EQ | XN_FLAG_FN_LN | XN_FLAG_FN_ALIGN;

struct stack_st_X509_REVOKED;
alias sk_X509_REVOKED_compfunc = int function(const(X509_REVOKED*)* a, const(X509_REVOKED*)* b);
alias sk_X509_REVOKED_freefunc = void function(X509_REVOKED* a);
alias sk_X509_REVOKED_copyfunc = x509_revoked_st* function(const(X509_REVOKED)* a);
int sk_X509_REVOKED_num(const(stack_st_X509_REVOKED)* sk);
X509_REVOKED* sk_X509_REVOKED_value(const(stack_st_X509_REVOKED)* sk, int idx);
stack_st_X509_REVOKED* sk_X509_REVOKED_new(sk_X509_REVOKED_compfunc compare);
stack_st_X509_REVOKED* sk_X509_REVOKED_new_null();
void sk_X509_REVOKED_free(stack_st_X509_REVOKED* sk);
void sk_X509_REVOKED_zero(stack_st_X509_REVOKED* sk);
X509_REVOKED* sk_X509_REVOKED_delete(stack_st_X509_REVOKED* sk, int i);
X509_REVOKED* sk_X509_REVOKED_delete_ptr(stack_st_X509_REVOKED* sk, X509_REVOKED* ptr);
int sk_X509_REVOKED_push(stack_st_X509_REVOKED* sk, X509_REVOKED* ptr);
int sk_X509_REVOKED_unshift(stack_st_X509_REVOKED* sk, X509_REVOKED* ptr);
X509_REVOKED* sk_X509_REVOKED_pop(stack_st_X509_REVOKED* sk);
X509_REVOKED* sk_X509_REVOKED_shift(stack_st_X509_REVOKED* sk);
void sk_X509_REVOKED_pop_free(stack_st_X509_REVOKED* sk, sk_X509_REVOKED_freefunc freefunc);
int sk_X509_REVOKED_insert(stack_st_X509_REVOKED* sk, X509_REVOKED* ptr, int idx);
X509_REVOKED* sk_X509_REVOKED_set(stack_st_X509_REVOKED* sk, int idx, X509_REVOKED* ptr);
int sk_X509_REVOKED_find(stack_st_X509_REVOKED* sk, X509_REVOKED* ptr);
int sk_X509_REVOKED_find_ex(stack_st_X509_REVOKED* sk, X509_REVOKED* ptr);
void sk_X509_REVOKED_sort(stack_st_X509_REVOKED* sk);
int sk_X509_REVOKED_is_sorted(const(stack_st_X509_REVOKED)* sk);
stack_st_X509_REVOKED* sk_X509_REVOKED_dup(const(stack_st_X509_REVOKED)* sk);
stack_st_X509_REVOKED* sk_X509_REVOKED_deep_copy(const(stack_st_X509_REVOKED)* sk, sk_X509_REVOKED_copyfunc copyfunc, sk_X509_REVOKED_freefunc freefunc);
sk_X509_REVOKED_compfunc sk_X509_REVOKED_set_cmp_func(stack_st_X509_REVOKED* sk, sk_X509_REVOKED_compfunc compare);

struct X509_crl_info_st;
alias X509_CRL_INFO = X509_crl_info_st;

struct stack_st_X509_CRL;
alias sk_X509_CRL_compfunc = int function(const(X509_CRL*)* a, const(X509_CRL*)* b);
alias sk_X509_CRL_freefunc = void function(X509_CRL* a);
alias sk_X509_CRL_copyfunc = X509_crl_st* function(const(X509_CRL)* a);
int sk_X509_CRL_num(const(stack_st_X509_CRL)* sk);
X509_CRL* sk_X509_CRL_value(const(stack_st_X509_CRL)* sk, int idx);
stack_st_X509_CRL* sk_X509_CRL_new(sk_X509_CRL_compfunc compare);
stack_st_X509_CRL* sk_X509_CRL_new_null();
void sk_X509_CRL_free(stack_st_X509_CRL* sk);
void sk_X509_CRL_zero(stack_st_X509_CRL* sk);
X509_CRL* sk_X509_CRL_delete(stack_st_X509_CRL* sk, int i);
X509_CRL* sk_X509_CRL_delete_ptr(stack_st_X509_CRL* sk, X509_CRL* ptr);
int sk_X509_CRL_push(stack_st_X509_CRL* sk, X509_CRL* ptr);
int sk_X509_CRL_unshift(stack_st_X509_CRL* sk, X509_CRL* ptr);
X509_CRL* sk_X509_CRL_pop(stack_st_X509_CRL* sk);
X509_CRL* sk_X509_CRL_shift(stack_st_X509_CRL* sk);
void sk_X509_CRL_pop_free(stack_st_X509_CRL* sk, sk_X509_CRL_freefunc freefunc);
int sk_X509_CRL_insert(stack_st_X509_CRL* sk, X509_CRL* ptr, int idx);
X509_CRL* sk_X509_CRL_set(stack_st_X509_CRL* sk, int idx, X509_CRL* ptr);
int sk_X509_CRL_find(stack_st_X509_CRL* sk, X509_CRL* ptr);
int sk_X509_CRL_find_ex(stack_st_X509_CRL* sk, X509_CRL* ptr);
void sk_X509_CRL_sort(stack_st_X509_CRL* sk);
int sk_X509_CRL_is_sorted(const(stack_st_X509_CRL)* sk);
stack_st_X509_CRL* sk_X509_CRL_dup(const(stack_st_X509_CRL)* sk);
stack_st_X509_CRL* sk_X509_CRL_deep_copy(const(stack_st_X509_CRL)* sk, sk_X509_CRL_copyfunc copyfunc, sk_X509_CRL_freefunc freefunc);
sk_X509_CRL_compfunc sk_X509_CRL_set_cmp_func(stack_st_X509_CRL* sk, sk_X509_CRL_compfunc compare);

struct private_key_st
{
    int version_;
    /* The PKCS#8 data types */
    X509_ALGOR* enc_algor;
    ASN1_OCTET_STRING* enc_pkey; /* encrypted pub key */
    /* When decrypted, the following will not be NULL */
    EVP_PKEY* dec_pkey;
    /* used to encrypt and decrypt */
    int key_length;
    char* key_data;
    int key_free; /* true if we should auto free key_data */
    /* expanded version of 'enc_algor' */
    EVP_CIPHER_INFO cipher;
}

alias X509_PKEY = private_key_st;

struct X509_info_st
{
    X509* x509;
    X509_CRL* crl;
    X509_PKEY* x_pkey;
    EVP_CIPHER_INFO enc_cipher;
    int enc_len;
    char* enc_data;
}

alias X509_INFO = X509_info_st;

struct stack_st_X509_INFO;
alias sk_X509_INFO_compfunc = int function(const(X509_INFO*)* a, const(X509_INFO*)* b);
alias sk_X509_INFO_freefunc = void function(X509_INFO* a);
alias sk_X509_INFO_copyfunc = X509_info_st* function(const(X509_INFO)* a);
int sk_X509_INFO_num(const(stack_st_X509_INFO)* sk);
X509_INFO* sk_X509_INFO_value(const(stack_st_X509_INFO)* sk, int idx);
stack_st_X509_INFO* sk_X509_INFO_new(sk_X509_INFO_compfunc compare);
stack_st_X509_INFO* sk_X509_INFO_new_null();
void sk_X509_INFO_free(stack_st_X509_INFO* sk);
void sk_X509_INFO_zero(stack_st_X509_INFO* sk);
X509_INFO* sk_X509_INFO_delete(stack_st_X509_INFO* sk, int i);
X509_INFO* sk_X509_INFO_delete_ptr(stack_st_X509_INFO* sk, X509_INFO* ptr);
int sk_X509_INFO_push(stack_st_X509_INFO* sk, X509_INFO* ptr);
int sk_X509_INFO_unshift(stack_st_X509_INFO* sk, X509_INFO* ptr);
X509_INFO* sk_X509_INFO_pop(stack_st_X509_INFO* sk);
X509_INFO* sk_X509_INFO_shift(stack_st_X509_INFO* sk);
void sk_X509_INFO_pop_free(stack_st_X509_INFO* sk, sk_X509_INFO_freefunc freefunc);
int sk_X509_INFO_insert(stack_st_X509_INFO* sk, X509_INFO* ptr, int idx);
X509_INFO* sk_X509_INFO_set(stack_st_X509_INFO* sk, int idx, X509_INFO* ptr);
int sk_X509_INFO_find(stack_st_X509_INFO* sk, X509_INFO* ptr);
int sk_X509_INFO_find_ex(stack_st_X509_INFO* sk, X509_INFO* ptr);
void sk_X509_INFO_sort(stack_st_X509_INFO* sk);
int sk_X509_INFO_is_sorted(const(stack_st_X509_INFO)* sk);
stack_st_X509_INFO* sk_X509_INFO_dup(const(stack_st_X509_INFO)* sk);
stack_st_X509_INFO* sk_X509_INFO_deep_copy(const(stack_st_X509_INFO)* sk, sk_X509_INFO_copyfunc copyfunc, sk_X509_INFO_freefunc freefunc);
sk_X509_INFO_compfunc sk_X509_INFO_set_cmp_func(stack_st_X509_INFO* sk, sk_X509_INFO_compfunc compare);

/*
 * The next 2 structures and their 8 routines were sent to me by Pat Richard
 * <patr@x509.com> and are used to manipulate Netscapes spki structures -
 * useful if you are writing a CA web page
 */
struct Netscape_spkac_st
{
    X509_PUBKEY* pubkey;
    ASN1_IA5STRING* challenge; /* challenge sent in atlas >= PR2 */
}

alias NETSCAPE_SPKAC = Netscape_spkac_st;

struct Netscape_spki_st
{
    NETSCAPE_SPKAC* spkac; /* signed public key and challenge */
    X509_ALGOR sig_algor;
    ASN1_BIT_STRING* signature;
}

alias NETSCAPE_SPKI = Netscape_spki_st;

/* Netscape certificate sequence structure */
struct Netscape_certificate_sequence
{
    ASN1_OBJECT* type;
    stack_st_X509* certs;
}

alias NETSCAPE_CERT_SEQUENCE = Netscape_certificate_sequence;

/*- Unused (and iv length is wrong)
typedef struct CBCParameter_st
        {
        unsigned char iv[8];
        } CBC_PARAM;
*/

/* Password based encryption structure */

struct PBEPARAM_st
{
    ASN1_OCTET_STRING* salt;
    ASN1_INTEGER* iter;
}

alias PBEPARAM = PBEPARAM_st;

/* Password based encryption V2 structures */

struct PBE2PARAM_st
{
    X509_ALGOR* keyfunc;
    X509_ALGOR* encryption;
}

alias PBE2PARAM = PBE2PARAM_st;

struct PBKDF2PARAM_st
{
    /* Usually OCTET STRING but could be anything */
    ASN1_TYPE* salt;
    ASN1_INTEGER* iter;
    ASN1_INTEGER* keylength;
    X509_ALGOR* prf;
}

alias PBKDF2PARAM = PBKDF2PARAM_st;

enum X509_EXT_PACK_UNKNOWN = 1;
enum X509_EXT_PACK_STRING = 2;

alias X509_extract_key = X509_get_pubkey; /*****/
alias X509_REQ_extract_key = X509_REQ_get_pubkey;
alias X509_name_cmp = X509_NAME_cmp;

void X509_CRL_set_default_method(const(X509_CRL_METHOD)* meth);
X509_CRL_METHOD* X509_CRL_METHOD_new(
    int function(X509_CRL* crl) crl_init,
    int function(X509_CRL* crl) crl_free,
    int function(X509_CRL* crl, X509_REVOKED** ret, ASN1_INTEGER* ser, X509_NAME* issuer) crl_lookup,
    int function(X509_CRL* crl, EVP_PKEY* pk) crl_verify);
void X509_CRL_METHOD_free(X509_CRL_METHOD* m);

void X509_CRL_set_meth_data(X509_CRL* crl, void* dat);
void* X509_CRL_get_meth_data(X509_CRL* crl);

const(char)* X509_verify_cert_error_string(c_long n);

int X509_verify(X509* a, EVP_PKEY* r);

int X509_REQ_verify(X509_REQ* a, EVP_PKEY* r);
int X509_CRL_verify(X509_CRL* a, EVP_PKEY* r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI* a, EVP_PKEY* r);

NETSCAPE_SPKI* NETSCAPE_SPKI_b64_decode(const(char)* str, int len);
char* NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI* x);
EVP_PKEY* NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI* x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI* x, EVP_PKEY* pkey);

int NETSCAPE_SPKI_print(BIO* out_, NETSCAPE_SPKI* spki);

int X509_signature_dump(BIO* bp, const(ASN1_STRING)* sig, int indent);
int X509_signature_print(
    BIO* bp,
    const(X509_ALGOR)* alg,
    const(ASN1_STRING)* sig);

int X509_sign(X509* x, EVP_PKEY* pkey, const(EVP_MD)* md);
int X509_sign_ctx(X509* x, EVP_MD_CTX* ctx);

version(OPENSSL_NO_OCSP) {} else {
int X509_http_nbio(OCSP_REQ_CTX* rctx, X509** pcert);
}

int X509_REQ_sign(X509_REQ* x, EVP_PKEY* pkey, const(EVP_MD)* md);
int X509_REQ_sign_ctx(X509_REQ* x, EVP_MD_CTX* ctx);
int X509_CRL_sign(X509_CRL* x, EVP_PKEY* pkey, const(EVP_MD)* md);
int X509_CRL_sign_ctx(X509_CRL* x, EVP_MD_CTX* ctx);

version(OPENSSL_NO_OCSP) {} else {
int X509_CRL_http_nbio(OCSP_REQ_CTX* rctx, X509_CRL** pcrl);
}

int NETSCAPE_SPKI_sign(NETSCAPE_SPKI* x, EVP_PKEY* pkey, const(EVP_MD)* md);

int X509_pubkey_digest(
    const(X509)* data,
    const(EVP_MD)* type,
    ubyte* md,
    uint* len);
int X509_digest(const(X509)* data, const(EVP_MD)* type, ubyte* md, uint* len);
int X509_CRL_digest(
    const(X509_CRL)* data,
    const(EVP_MD)* type,
    ubyte* md,
    uint* len);
int X509_REQ_digest(
    const(X509_REQ)* data,
    const(EVP_MD)* type,
    ubyte* md,
    uint* len);
int X509_NAME_digest(
    const(X509_NAME)* data,
    const(EVP_MD)* type,
    ubyte* md,
    uint* len);

version(OPENSSL_NO_STDIO) {} else {
X509* d2i_X509_fp(FILE* fp, X509** x509);
int i2d_X509_fp(FILE* fp, X509* x509);
X509_CRL* d2i_X509_CRL_fp(FILE* fp, X509_CRL** crl);
int i2d_X509_CRL_fp(FILE* fp, X509_CRL* crl);
X509_REQ* d2i_X509_REQ_fp(FILE* fp, X509_REQ** req);
int i2d_X509_REQ_fp(FILE* fp, X509_REQ* req);

version(OPENSSL_NO_RSA) {} else {
RSA* d2i_RSAPrivateKey_fp(FILE* fp, RSA** rsa);
int i2d_RSAPrivateKey_fp(FILE* fp, RSA* rsa);
RSA* d2i_RSAPublicKey_fp(FILE* fp, RSA** rsa);
int i2d_RSAPublicKey_fp(FILE* fp, RSA* rsa);
RSA* d2i_RSA_PUBKEY_fp(FILE* fp, RSA** rsa);
int i2d_RSA_PUBKEY_fp(FILE* fp, RSA* rsa);
}

version(OPENSSL_NO_DSA) {} else {
DSA* d2i_DSA_PUBKEY_fp(FILE* fp, DSA** dsa);
int i2d_DSA_PUBKEY_fp(FILE* fp, DSA* dsa);
DSA* d2i_DSAPrivateKey_fp(FILE* fp, DSA** dsa);
int i2d_DSAPrivateKey_fp(FILE* fp, DSA* dsa);
}

version(OPENSSL_NO_EC) {} else {
EC_KEY* d2i_EC_PUBKEY_fp(FILE* fp, EC_KEY** eckey);
int i2d_EC_PUBKEY_fp(FILE* fp, EC_KEY* eckey);
EC_KEY* d2i_ECPrivateKey_fp(FILE* fp, EC_KEY** eckey);
int i2d_ECPrivateKey_fp(FILE* fp, EC_KEY* eckey);
}

X509_SIG* d2i_PKCS8_fp(FILE* fp, X509_SIG** p8);
int i2d_PKCS8_fp(FILE* fp, X509_SIG* p8);
PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO_fp(
    FILE* fp,
    PKCS8_PRIV_KEY_INFO** p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE* fp, PKCS8_PRIV_KEY_INFO* p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE* fp, EVP_PKEY* key);
int i2d_PrivateKey_fp(FILE* fp, EVP_PKEY* pkey);
EVP_PKEY* d2i_PrivateKey_fp(FILE* fp, EVP_PKEY** a);
int i2d_PUBKEY_fp(FILE* fp, EVP_PKEY* pkey);
EVP_PKEY* d2i_PUBKEY_fp(FILE* fp, EVP_PKEY** a);
} /+ OPENSSL_NO_STDIO +/
X509* d2i_X509_bio(BIO* bp, X509** x509);
int i2d_X509_bio(BIO* bp, X509* x509);
X509_CRL* d2i_X509_CRL_bio(BIO* bp, X509_CRL** crl);
int i2d_X509_CRL_bio(BIO* bp, X509_CRL* crl);
X509_REQ* d2i_X509_REQ_bio(BIO* bp, X509_REQ** req);
int i2d_X509_REQ_bio(BIO* bp, X509_REQ* req);

version(OPENSSL_NO_RSA) {} else {
RSA* d2i_RSAPrivateKey_bio(BIO* bp, RSA** rsa);
int i2d_RSAPrivateKey_bio(BIO* bp, RSA* rsa);
RSA* d2i_RSAPublicKey_bio(BIO* bp, RSA** rsa);
int i2d_RSAPublicKey_bio(BIO* bp, RSA* rsa);
RSA* d2i_RSA_PUBKEY_bio(BIO* bp, RSA** rsa);
int i2d_RSA_PUBKEY_bio(BIO* bp, RSA* rsa);
}

version(OPENSSL_NO_DSA) {} else {
DSA* d2i_DSA_PUBKEY_bio(BIO* bp, DSA** dsa);
int i2d_DSA_PUBKEY_bio(BIO* bp, DSA* dsa);
DSA* d2i_DSAPrivateKey_bio(BIO* bp, DSA** dsa);
int i2d_DSAPrivateKey_bio(BIO* bp, DSA* dsa);
}

version(OPENSSL_NO_EC) {} else {
EC_KEY* d2i_EC_PUBKEY_bio(BIO* bp, EC_KEY** eckey);
int i2d_EC_PUBKEY_bio(BIO* bp, EC_KEY* eckey);
EC_KEY* d2i_ECPrivateKey_bio(BIO* bp, EC_KEY** eckey);
int i2d_ECPrivateKey_bio(BIO* bp, EC_KEY* eckey);
}

X509_SIG* d2i_PKCS8_bio(BIO* bp, X509_SIG** p8);
int i2d_PKCS8_bio(BIO* bp, X509_SIG* p8);
PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO_bio(
    BIO* bp,
    PKCS8_PRIV_KEY_INFO** p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO* bp, PKCS8_PRIV_KEY_INFO* p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO* bp, EVP_PKEY* key);
int i2d_PrivateKey_bio(BIO* bp, EVP_PKEY* pkey);
EVP_PKEY* d2i_PrivateKey_bio(BIO* bp, EVP_PKEY** a);
int i2d_PUBKEY_bio(BIO* bp, EVP_PKEY* pkey);
EVP_PKEY* d2i_PUBKEY_bio(BIO* bp, EVP_PKEY** a);

X509* X509_dup(X509* x509);
X509_ATTRIBUTE* X509_ATTRIBUTE_dup(X509_ATTRIBUTE* xa);
X509_EXTENSION* X509_EXTENSION_dup(X509_EXTENSION* ex);
X509_CRL* X509_CRL_dup(X509_CRL* crl);
X509_REVOKED* X509_REVOKED_dup(X509_REVOKED* rev);
X509_REQ* X509_REQ_dup(X509_REQ* req);
X509_ALGOR* X509_ALGOR_dup(X509_ALGOR* xn);
int X509_ALGOR_set0(X509_ALGOR* alg, ASN1_OBJECT* aobj, int ptype, void* pval);
void X509_ALGOR_get0(
    const(ASN1_OBJECT*)* paobj,
    int* pptype,
    const(void*)* ppval,
    const(X509_ALGOR)* algor);
void X509_ALGOR_set_md(X509_ALGOR* alg, const(EVP_MD)* md);
int X509_ALGOR_cmp(const(X509_ALGOR)* a, const(X509_ALGOR)* b);

X509_NAME* X509_NAME_dup(X509_NAME* xn);
X509_NAME_ENTRY* X509_NAME_ENTRY_dup(X509_NAME_ENTRY* ne);

int X509_cmp_time(const(ASN1_TIME)* s, time_t* t);
int X509_cmp_current_time(const(ASN1_TIME)* s);
ASN1_TIME* X509_time_adj(ASN1_TIME* s, c_long adj, time_t* t);
ASN1_TIME* X509_time_adj_ex(
    ASN1_TIME* s,
    int offset_day,
    c_long offset_sec,
    time_t* t);
ASN1_TIME* X509_gmtime_adj(ASN1_TIME* s, c_long adj);

const(char)* X509_get_default_cert_area();
const(char)* X509_get_default_cert_dir();
const(char)* X509_get_default_cert_file();
const(char)* X509_get_default_cert_dir_env();
const(char)* X509_get_default_cert_file_env();
const(char)* X509_get_default_private_dir();

X509_REQ* X509_to_X509_REQ(X509* x, EVP_PKEY* pkey, const(EVP_MD)* md);
X509* X509_REQ_to_X509(X509_REQ* r, int days, EVP_PKEY* pkey);

X509_ALGOR* X509_ALGOR_new();
void X509_ALGOR_free(X509_ALGOR* a);
X509_ALGOR* d2i_X509_ALGOR(X509_ALGOR** a, const(ubyte*)* in_, c_long len);
int i2d_X509_ALGOR(X509_ALGOR* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_ALGOR_it;
X509_ALGORS* d2i_X509_ALGORS(X509_ALGORS** a, const(ubyte*)* in_, c_long len);
int i2d_X509_ALGORS(X509_ALGORS* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_ALGORS_it;
X509_VAL* X509_VAL_new();
void X509_VAL_free(X509_VAL* a);
X509_VAL* d2i_X509_VAL(X509_VAL** a, const(ubyte*)* in_, c_long len);
int i2d_X509_VAL(X509_VAL* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_VAL_it;

X509_PUBKEY* X509_PUBKEY_new();
void X509_PUBKEY_free(X509_PUBKEY* a);
X509_PUBKEY* d2i_X509_PUBKEY(X509_PUBKEY** a, const(ubyte*)* in_, c_long len);
int i2d_X509_PUBKEY(X509_PUBKEY* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_PUBKEY_it;

int X509_PUBKEY_set(X509_PUBKEY** x, EVP_PKEY* pkey);
EVP_PKEY* X509_PUBKEY_get0(X509_PUBKEY* key);
EVP_PKEY* X509_PUBKEY_get(X509_PUBKEY* key);
int X509_get_pubkey_parameters(EVP_PKEY* pkey, stack_st_X509* chain);
c_long X509_get_pathlen(X509* x);
int i2d_PUBKEY(EVP_PKEY* a, ubyte** pp);
EVP_PKEY* d2i_PUBKEY(EVP_PKEY** a, const(ubyte*)* pp, c_long length);

version(OPENSSL_NO_RSA) {} else {
int i2d_RSA_PUBKEY(RSA* a, ubyte** pp);
RSA* d2i_RSA_PUBKEY(RSA** a, const(ubyte*)* pp, c_long length);
}

version(OPENSSL_NO_DSA) {} else {
int i2d_DSA_PUBKEY(DSA* a, ubyte** pp);
DSA* d2i_DSA_PUBKEY(DSA** a, const(ubyte*)* pp, c_long length);
}

version(OPENSSL_NO_EC) {} else {
int i2d_EC_PUBKEY(EC_KEY* a, ubyte** pp);
EC_KEY* d2i_EC_PUBKEY(EC_KEY** a, const(ubyte*)* pp, c_long length);
}

X509_SIG* X509_SIG_new();
void X509_SIG_free(X509_SIG* a);
X509_SIG* d2i_X509_SIG(X509_SIG** a, const(ubyte*)* in_, c_long len);
int i2d_X509_SIG(X509_SIG* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_SIG_it;
void X509_SIG_get0(
    const(X509_SIG)* sig,
    const(X509_ALGOR*)* palg,
    const(ASN1_OCTET_STRING*)* pdigest);
void X509_SIG_getm(
    X509_SIG* sig,
    X509_ALGOR** palg,
    ASN1_OCTET_STRING** pdigest);

X509_REQ_INFO* X509_REQ_INFO_new();
void X509_REQ_INFO_free(X509_REQ_INFO* a);
X509_REQ_INFO* d2i_X509_REQ_INFO(X509_REQ_INFO** a, const(ubyte*)* in_, c_long len);
int i2d_X509_REQ_INFO(X509_REQ_INFO* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_REQ_INFO_it;
X509_REQ* X509_REQ_new();
void X509_REQ_free(X509_REQ* a);
X509_REQ* d2i_X509_REQ(X509_REQ** a, const(ubyte*)* in_, c_long len);
int i2d_X509_REQ(X509_REQ* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_REQ_it;

X509_ATTRIBUTE* X509_ATTRIBUTE_new();
void X509_ATTRIBUTE_free(X509_ATTRIBUTE* a);
X509_ATTRIBUTE* d2i_X509_ATTRIBUTE(X509_ATTRIBUTE** a, const(ubyte*)* in_, c_long len);
int i2d_X509_ATTRIBUTE(X509_ATTRIBUTE* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_ATTRIBUTE_it;
X509_ATTRIBUTE* X509_ATTRIBUTE_create(int nid, int atrtype, void* value);

X509_EXTENSION* X509_EXTENSION_new();
void X509_EXTENSION_free(X509_EXTENSION* a);
X509_EXTENSION* d2i_X509_EXTENSION(X509_EXTENSION** a, const(ubyte*)* in_, c_long len);
int i2d_X509_EXTENSION(X509_EXTENSION* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_EXTENSION_it;
X509_EXTENSIONS* d2i_X509_EXTENSIONS(X509_EXTENSIONS** a, const(ubyte*)* in_, c_long len);
int i2d_X509_EXTENSIONS(X509_EXTENSIONS* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_EXTENSIONS_it;

X509_NAME_ENTRY* X509_NAME_ENTRY_new();
void X509_NAME_ENTRY_free(X509_NAME_ENTRY* a);
X509_NAME_ENTRY* d2i_X509_NAME_ENTRY(X509_NAME_ENTRY** a, const(ubyte*)* in_, c_long len);
int i2d_X509_NAME_ENTRY(X509_NAME_ENTRY* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_NAME_ENTRY_it;

X509_NAME* X509_NAME_new();
void X509_NAME_free(X509_NAME* a);
X509_NAME* d2i_X509_NAME(X509_NAME** a, const(ubyte*)* in_, c_long len);
int i2d_X509_NAME(X509_NAME* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_NAME_it;

int X509_NAME_set(X509_NAME** xn, X509_NAME* name);

X509_CINF* X509_CINF_new();
void X509_CINF_free(X509_CINF* a);
X509_CINF* d2i_X509_CINF(X509_CINF** a, const(ubyte*)* in_, c_long len);
int i2d_X509_CINF(X509_CINF* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_CINF_it;

X509* X509_new();
void X509_free(X509* a);
X509* d2i_X509(X509** a, const(ubyte*)* in_, c_long len);
int i2d_X509(X509* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_it;
X509_CERT_AUX* X509_CERT_AUX_new();
void X509_CERT_AUX_free(X509_CERT_AUX* a);
X509_CERT_AUX* d2i_X509_CERT_AUX(X509_CERT_AUX** a, const(ubyte*)* in_, c_long len);
int i2d_X509_CERT_AUX(X509_CERT_AUX* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_CERT_AUX_it;

extern (D) auto X509_get_ex_new_index(T0, T1, T2, T3, T4)(auto ref T0 l, auto ref T1 p, auto ref T2 newf, auto ref T3 dupf, auto ref T4 freef)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, l, p, newf, dupf, freef);
}

int X509_set_ex_data(X509* r, int idx, void* arg);
void* X509_get_ex_data(X509* r, int idx);
int i2d_X509_AUX(X509* a, ubyte** pp);
X509* d2i_X509_AUX(X509** a, const(ubyte*)* pp, c_long length);

int i2d_re_X509_tbs(X509* x, ubyte** pp);

void X509_get0_signature(
    const(ASN1_BIT_STRING*)* psig,
    const(X509_ALGOR*)* palg,
    const(X509)* x);
int X509_get_signature_nid(const(X509)* x);

int X509_trusted(const(X509)* x);
int X509_alias_set1(X509* x, const(ubyte)* name, int len);
int X509_keyid_set1(X509* x, const(ubyte)* id, int len);
ubyte* X509_alias_get0(X509* x, int* len);
ubyte* X509_keyid_get0(X509* x, int* len);
int function(int, X509*, int, int function(int, X509*, int) trust) X509_TRUST_set_default(
    int,
    X509*,
    int,
    int function(int, X509*, int) trust);
int X509_TRUST_set(int* t, int trust);
int X509_add1_trust_object(X509* x, const(ASN1_OBJECT)* obj);
int X509_add1_reject_object(X509* x, const(ASN1_OBJECT)* obj);
void X509_trust_clear(X509* x);
void X509_reject_clear(X509* x);

stack_st_ASN1_OBJECT* X509_get0_trust_objects(X509* x);
stack_st_ASN1_OBJECT* X509_get0_reject_objects(X509* x);

X509_REVOKED* X509_REVOKED_new();
void X509_REVOKED_free(X509_REVOKED* a);
X509_REVOKED* d2i_X509_REVOKED(X509_REVOKED** a, const(ubyte*)* in_, c_long len);
int i2d_X509_REVOKED(X509_REVOKED* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_REVOKED_it;
X509_CRL_INFO* X509_CRL_INFO_new();
void X509_CRL_INFO_free(X509_CRL_INFO* a);
X509_CRL_INFO* d2i_X509_CRL_INFO(X509_CRL_INFO** a, const(ubyte*)* in_, c_long len);
int i2d_X509_CRL_INFO(X509_CRL_INFO* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_CRL_INFO_it;
X509_CRL* X509_CRL_new();
void X509_CRL_free(X509_CRL* a);
X509_CRL* d2i_X509_CRL(X509_CRL** a, const(ubyte*)* in_, c_long len);
int i2d_X509_CRL(X509_CRL* a, ubyte** out_);
extern __gshared const ASN1_ITEM X509_CRL_it;

int X509_CRL_add0_revoked(X509_CRL* crl, X509_REVOKED* rev);
int X509_CRL_get0_by_serial(
    X509_CRL* crl,
    X509_REVOKED** ret,
    ASN1_INTEGER* serial);
int X509_CRL_get0_by_cert(X509_CRL* crl, X509_REVOKED** ret, X509* x);

X509_PKEY* X509_PKEY_new();
void X509_PKEY_free(X509_PKEY* a);

NETSCAPE_SPKI* NETSCAPE_SPKI_new();
void NETSCAPE_SPKI_free(NETSCAPE_SPKI* a);
NETSCAPE_SPKI* d2i_NETSCAPE_SPKI(NETSCAPE_SPKI** a, const(ubyte*)* in_, c_long len);
int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI* a, ubyte** out_);
extern __gshared const ASN1_ITEM NETSCAPE_SPKI_it;
NETSCAPE_SPKAC* NETSCAPE_SPKAC_new();
void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC* a);
NETSCAPE_SPKAC* d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC** a, const(ubyte*)* in_, c_long len);
int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC* a, ubyte** out_);
extern __gshared const ASN1_ITEM NETSCAPE_SPKAC_it;
NETSCAPE_CERT_SEQUENCE* NETSCAPE_CERT_SEQUENCE_new();
void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE* a);
NETSCAPE_CERT_SEQUENCE* d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE** a, const(ubyte*)* in_, c_long len);
int i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE* a, ubyte** out_);
extern __gshared const ASN1_ITEM NETSCAPE_CERT_SEQUENCE_it;

X509_INFO* X509_INFO_new();
void X509_INFO_free(X509_INFO* a);
char* X509_NAME_oneline(const(X509_NAME)* a, char* buf, int size);

int ASN1_verify(
    int function() i2d,
    X509_ALGOR* algor1,
    ASN1_BIT_STRING* signature,
    char* data,
    EVP_PKEY* pkey);

int ASN1_digest(
    int function() i2d,
    const(EVP_MD)* type,
    char* data,
    ubyte* md,
    uint* len);

int ASN1_sign(
    int function() i2d,
    X509_ALGOR* algor1,
    X509_ALGOR* algor2,
    ASN1_BIT_STRING* signature,
    char* data,
    EVP_PKEY* pkey,
    const(EVP_MD)* type);

int ASN1_item_digest(
    const(ASN1_ITEM)* it,
    const(EVP_MD)* type,
    void* data,
    ubyte* md,
    uint* len);

int ASN1_item_verify(
    const(ASN1_ITEM)* it,
    X509_ALGOR* algor1,
    ASN1_BIT_STRING* signature,
    void* data,
    EVP_PKEY* pkey);

int ASN1_item_sign(
    const(ASN1_ITEM)* it,
    X509_ALGOR* algor1,
    X509_ALGOR* algor2,
    ASN1_BIT_STRING* signature,
    void* data,
    EVP_PKEY* pkey,
    const(EVP_MD)* type);
int ASN1_item_sign_ctx(
    const(ASN1_ITEM)* it,
    X509_ALGOR* algor1,
    X509_ALGOR* algor2,
    ASN1_BIT_STRING* signature,
    void* asn,
    EVP_MD_CTX* ctx);

c_long X509_get_version(const(X509)* x);
int X509_set_version(X509* x, c_long version_);
int X509_set_serialNumber(X509* x, ASN1_INTEGER* serial);
ASN1_INTEGER* X509_get_serialNumber(X509* x);
const(ASN1_INTEGER)* X509_get0_serialNumber(const(X509)* x);
int X509_set_issuer_name(X509* x, X509_NAME* name);
X509_NAME* X509_get_issuer_name(const(X509)* a);
int X509_set_subject_name(X509* x, X509_NAME* name);
X509_NAME* X509_get_subject_name(const(X509)* a);
const(ASN1_TIME)* X509_get0_notBefore(const(X509)* x);
ASN1_TIME* X509_getm_notBefore(const(X509)* x);
int X509_set1_notBefore(X509* x, const(ASN1_TIME)* tm);
const(ASN1_TIME)* X509_get0_notAfter(const(X509)* x);
ASN1_TIME* X509_getm_notAfter(const(X509)* x);
int X509_set1_notAfter(X509* x, const(ASN1_TIME)* tm);
int X509_set_pubkey(X509* x, EVP_PKEY* pkey);
int X509_up_ref(X509* x);
int X509_get_signature_type(const(X509)* x);

alias X509_get_notBefore = X509_getm_notBefore;
alias X509_get_notAfter = X509_getm_notAfter;
alias X509_set_notBefore = X509_set1_notBefore;
alias X509_set_notAfter = X509_set1_notAfter;

/*
 * This one is only used so that a binary form can output, as in
 * i2d_X509_NAME(X509_get_X509_PUBKEY(x), &buf)
 */
X509_PUBKEY* X509_get_X509_PUBKEY(const(X509)* x);
const(stack_st_X509_EXTENSION)* X509_get0_extensions(const(X509)* x);
void X509_get0_uids(
    const(X509)* x,
    const(ASN1_BIT_STRING*)* piuid,
    const(ASN1_BIT_STRING*)* psuid);
const(X509_ALGOR)* X509_get0_tbs_sigalg(const(X509)* x);

EVP_PKEY* X509_get0_pubkey(const(X509)* x);
EVP_PKEY* X509_get_pubkey(X509* x);
ASN1_BIT_STRING* X509_get0_pubkey_bitstr(const(X509)* x);
int X509_certificate_type(const(X509)* x, const(EVP_PKEY)* pubkey);

c_long X509_REQ_get_version(const(X509_REQ)* req);
int X509_REQ_set_version(X509_REQ* x, c_long version_);
X509_NAME* X509_REQ_get_subject_name(const(X509_REQ)* req);
int X509_REQ_set_subject_name(X509_REQ* req, X509_NAME* name);
void X509_REQ_get0_signature(
    const(X509_REQ)* req,
    const(ASN1_BIT_STRING*)* psig,
    const(X509_ALGOR*)* palg);
int X509_REQ_get_signature_nid(const(X509_REQ)* req);
int i2d_re_X509_REQ_tbs(X509_REQ* req, ubyte** pp);
int X509_REQ_set_pubkey(X509_REQ* x, EVP_PKEY* pkey);
EVP_PKEY* X509_REQ_get_pubkey(X509_REQ* req);
EVP_PKEY* X509_REQ_get0_pubkey(X509_REQ* req);
X509_PUBKEY* X509_REQ_get_X509_PUBKEY(X509_REQ* req);
int X509_REQ_extension_nid(int nid);
int* X509_REQ_get_extension_nids();
void X509_REQ_set_extension_nids(int* nids);
stack_st_X509_EXTENSION* X509_REQ_get_extensions(X509_REQ* req);
int X509_REQ_add_extensions_nid(
    X509_REQ* req,
    stack_st_X509_EXTENSION* exts,
    int nid);
int X509_REQ_add_extensions(X509_REQ* req, stack_st_X509_EXTENSION* exts);
int X509_REQ_get_attr_count(const(X509_REQ)* req);
int X509_REQ_get_attr_by_NID(const(X509_REQ)* req, int nid, int lastpos);
int X509_REQ_get_attr_by_OBJ(
    const(X509_REQ)* req,
    const(ASN1_OBJECT)* obj,
    int lastpos);
X509_ATTRIBUTE* X509_REQ_get_attr(const(X509_REQ)* req, int loc);
X509_ATTRIBUTE* X509_REQ_delete_attr(X509_REQ* req, int loc);
int X509_REQ_add1_attr(X509_REQ* req, X509_ATTRIBUTE* attr);
int X509_REQ_add1_attr_by_OBJ(
    X509_REQ* req,
    const(ASN1_OBJECT)* obj,
    int type,
    const(ubyte)* bytes,
    int len);
int X509_REQ_add1_attr_by_NID(
    X509_REQ* req,
    int nid,
    int type,
    const(ubyte)* bytes,
    int len);
int X509_REQ_add1_attr_by_txt(
    X509_REQ* req,
    const(char)* attrname,
    int type,
    const(ubyte)* bytes,
    int len);

int X509_CRL_set_version(X509_CRL* x, c_long version_);
int X509_CRL_set_issuer_name(X509_CRL* x, X509_NAME* name);
int X509_CRL_set1_lastUpdate(X509_CRL* x, const(ASN1_TIME)* tm);
int X509_CRL_set1_nextUpdate(X509_CRL* x, const(ASN1_TIME)* tm);
int X509_CRL_sort(X509_CRL* crl);
int X509_CRL_up_ref(X509_CRL* crl);

alias X509_CRL_set_lastUpdate = X509_CRL_set1_lastUpdate;
alias X509_CRL_set_nextUpdate = X509_CRL_set1_nextUpdate;

c_long X509_CRL_get_version(const(X509_CRL)* crl);
const(ASN1_TIME)* X509_CRL_get0_lastUpdate(const(X509_CRL)* crl);
const(ASN1_TIME)* X509_CRL_get0_nextUpdate(const(X509_CRL)* crl);
ASN1_TIME* X509_CRL_get_lastUpdate(X509_CRL* crl);
ASN1_TIME* X509_CRL_get_nextUpdate(X509_CRL* crl);
X509_NAME* X509_CRL_get_issuer(const(X509_CRL)* crl);
const(stack_st_X509_EXTENSION)* X509_CRL_get0_extensions(const(X509_CRL)* crl);
stack_st_X509_REVOKED* X509_CRL_get_REVOKED(X509_CRL* crl);
void X509_CRL_get0_signature(
    const(X509_CRL)* crl,
    const(ASN1_BIT_STRING*)* psig,
    const(X509_ALGOR*)* palg);
int X509_CRL_get_signature_nid(const(X509_CRL)* crl);
int i2d_re_X509_CRL_tbs(X509_CRL* req, ubyte** pp);

const(ASN1_INTEGER)* X509_REVOKED_get0_serialNumber(const(X509_REVOKED)* x);
int X509_REVOKED_set_serialNumber(X509_REVOKED* x, ASN1_INTEGER* serial);
const(ASN1_TIME)* X509_REVOKED_get0_revocationDate(const(X509_REVOKED)* x);
int X509_REVOKED_set_revocationDate(X509_REVOKED* r, ASN1_TIME* tm);
const(stack_st_X509_EXTENSION)* X509_REVOKED_get0_extensions(
    const(X509_REVOKED)* r);

X509_CRL* X509_CRL_diff(
    X509_CRL* base,
    X509_CRL* newer,
    EVP_PKEY* skey,
    const(EVP_MD)* md,
    uint flags);

int X509_REQ_check_private_key(X509_REQ* x509, EVP_PKEY* pkey);

int X509_check_private_key(const(X509)* x509, const(EVP_PKEY)* pkey);
int X509_chain_check_suiteb(
    int* perror_depth,
    X509* x,
    stack_st_X509* chain,
    c_ulong flags);
int X509_CRL_check_suiteb(X509_CRL* crl, EVP_PKEY* pk, c_ulong flags);
stack_st_X509* X509_chain_up_ref(stack_st_X509* chain);

int X509_issuer_and_serial_cmp(const(X509)* a, const(X509)* b);
c_ulong X509_issuer_and_serial_hash(X509* a);

int X509_issuer_name_cmp(const(X509)* a, const(X509)* b);
c_ulong X509_issuer_name_hash(X509* a);

int X509_subject_name_cmp(const(X509)* a, const(X509)* b);
c_ulong X509_subject_name_hash(X509* x);

version(OPENSSL_NO_MD5) {} else {
c_ulong X509_issuer_name_hash_old(X509* a);
c_ulong X509_subject_name_hash_old(X509* x);
}

int X509_cmp(const(X509)* a, const(X509)* b);
int X509_NAME_cmp(const(X509_NAME)* a, const(X509_NAME)* b);
c_ulong X509_NAME_hash(X509_NAME* x);
c_ulong X509_NAME_hash_old(X509_NAME* x);

int X509_CRL_cmp(const(X509_CRL)* a, const(X509_CRL)* b);
int X509_CRL_match(const(X509_CRL)* a, const(X509_CRL)* b);
int X509_aux_print(BIO* out_, X509* x, int indent);

version(OPENSSL_NO_STDIO) {} else {
int X509_print_ex_fp(FILE* bp, X509* x, c_ulong nmflag, c_ulong cflag);
int X509_print_fp(FILE* bp, X509* x);
int X509_CRL_print_fp(FILE* bp, X509_CRL* x);
int X509_REQ_print_fp(FILE* bp, X509_REQ* req);
int X509_NAME_print_ex_fp(
    FILE* fp,
    const(X509_NAME)* nm,
    int indent,
    c_ulong flags);
}

int X509_NAME_print(BIO* bp, const(X509_NAME)* name, int obase);
int X509_NAME_print_ex(
    BIO* out_,
    const(X509_NAME)* nm,
    int indent,
    c_ulong flags);
int X509_print_ex(BIO* bp, X509* x, c_ulong nmflag, c_ulong cflag);
int X509_print(BIO* bp, X509* x);
int X509_ocspid_print(BIO* bp, X509* x);
int X509_CRL_print(BIO* bp, X509_CRL* x);
int X509_REQ_print_ex(BIO* bp, X509_REQ* x, c_ulong nmflag, c_ulong cflag);
int X509_REQ_print(BIO* bp, X509_REQ* req);

int X509_NAME_entry_count(const(X509_NAME)* name);
int X509_NAME_get_text_by_NID(X509_NAME* name, int nid, char* buf, int len);
int X509_NAME_get_text_by_OBJ(
    X509_NAME* name,
    const(ASN1_OBJECT)* obj,
    char* buf,
    int len);

/*
 * NOTE: you should be passing -1, not 0 as lastpos. The functions that use
 * lastpos, search after that position on.
 */
int X509_NAME_get_index_by_NID(X509_NAME* name, int nid, int lastpos);
int X509_NAME_get_index_by_OBJ(
    X509_NAME* name,
    const(ASN1_OBJECT)* obj,
    int lastpos);
X509_NAME_ENTRY* X509_NAME_get_entry(const(X509_NAME)* name, int loc);
X509_NAME_ENTRY* X509_NAME_delete_entry(X509_NAME* name, int loc);
int X509_NAME_add_entry(
    X509_NAME* name,
    const(X509_NAME_ENTRY)* ne,
    int loc,
    int set);
int X509_NAME_add_entry_by_OBJ(
    X509_NAME* name,
    const(ASN1_OBJECT)* obj,
    int type,
    const(ubyte)* bytes,
    int len,
    int loc,
    int set);
int X509_NAME_add_entry_by_NID(
    X509_NAME* name,
    int nid,
    int type,
    const(ubyte)* bytes,
    int len,
    int loc,
    int set);
X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_txt(
    X509_NAME_ENTRY** ne,
    const(char)* field,
    int type,
    const(ubyte)* bytes,
    int len);
X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_NID(
    X509_NAME_ENTRY** ne,
    int nid,
    int type,
    const(ubyte)* bytes,
    int len);
int X509_NAME_add_entry_by_txt(
    X509_NAME* name,
    const(char)* field,
    int type,
    const(ubyte)* bytes,
    int len,
    int loc,
    int set);
X509_NAME_ENTRY* X509_NAME_ENTRY_create_by_OBJ(
    X509_NAME_ENTRY** ne,
    const(ASN1_OBJECT)* obj,
    int type,
    const(ubyte)* bytes,
    int len);
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY* ne, const(ASN1_OBJECT)* obj);
int X509_NAME_ENTRY_set_data(
    X509_NAME_ENTRY* ne,
    int type,
    const(ubyte)* bytes,
    int len);
ASN1_OBJECT* X509_NAME_ENTRY_get_object(const(X509_NAME_ENTRY)* ne);
ASN1_STRING* X509_NAME_ENTRY_get_data(const(X509_NAME_ENTRY)* ne);
int X509_NAME_ENTRY_set(const(X509_NAME_ENTRY)* ne);

int X509_NAME_get0_der(X509_NAME* nm, const(ubyte*)* pder, size_t* pderlen);

int X509v3_get_ext_count(const(stack_st_X509_EXTENSION)* x);
int X509v3_get_ext_by_NID(
    const(stack_st_X509_EXTENSION)* x,
    int nid,
    int lastpos);
int X509v3_get_ext_by_OBJ(
    const(stack_st_X509_EXTENSION)* x,
    const(ASN1_OBJECT)* obj,
    int lastpos);
int X509v3_get_ext_by_critical(
    const(stack_st_X509_EXTENSION)* x,
    int crit,
    int lastpos);
X509_EXTENSION* X509v3_get_ext(const(stack_st_X509_EXTENSION)* x, int loc);
X509_EXTENSION* X509v3_delete_ext(stack_st_X509_EXTENSION* x, int loc);
stack_st_X509_EXTENSION* X509v3_add_ext(
    stack_st_X509_EXTENSION** x,
    X509_EXTENSION* ex,
    int loc);

int X509_get_ext_count(const(X509)* x);
int X509_get_ext_by_NID(const(X509)* x, int nid, int lastpos);
int X509_get_ext_by_OBJ(const(X509)* x, const(ASN1_OBJECT)* obj, int lastpos);
int X509_get_ext_by_critical(const(X509)* x, int crit, int lastpos);
X509_EXTENSION* X509_get_ext(const(X509)* x, int loc);
X509_EXTENSION* X509_delete_ext(X509* x, int loc);
int X509_add_ext(X509* x, X509_EXTENSION* ex, int loc);
void* X509_get_ext_d2i(const(X509)* x, int nid, int* crit, int* idx);
int X509_add1_ext_i2d(X509* x, int nid, void* value, int crit, c_ulong flags);

int X509_CRL_get_ext_count(const(X509_CRL)* x);
int X509_CRL_get_ext_by_NID(const(X509_CRL)* x, int nid, int lastpos);
int X509_CRL_get_ext_by_OBJ(
    const(X509_CRL)* x,
    const(ASN1_OBJECT)* obj,
    int lastpos);
int X509_CRL_get_ext_by_critical(const(X509_CRL)* x, int crit, int lastpos);
X509_EXTENSION* X509_CRL_get_ext(const(X509_CRL)* x, int loc);
X509_EXTENSION* X509_CRL_delete_ext(X509_CRL* x, int loc);
int X509_CRL_add_ext(X509_CRL* x, X509_EXTENSION* ex, int loc);
void* X509_CRL_get_ext_d2i(const(X509_CRL)* x, int nid, int* crit, int* idx);
int X509_CRL_add1_ext_i2d(
    X509_CRL* x,
    int nid,
    void* value,
    int crit,
    c_ulong flags);

int X509_REVOKED_get_ext_count(const(X509_REVOKED)* x);
int X509_REVOKED_get_ext_by_NID(const(X509_REVOKED)* x, int nid, int lastpos);
int X509_REVOKED_get_ext_by_OBJ(
    const(X509_REVOKED)* x,
    const(ASN1_OBJECT)* obj,
    int lastpos);
int X509_REVOKED_get_ext_by_critical(
    const(X509_REVOKED)* x,
    int crit,
    int lastpos);
X509_EXTENSION* X509_REVOKED_get_ext(const(X509_REVOKED)* x, int loc);
X509_EXTENSION* X509_REVOKED_delete_ext(X509_REVOKED* x, int loc);
int X509_REVOKED_add_ext(X509_REVOKED* x, X509_EXTENSION* ex, int loc);
void* X509_REVOKED_get_ext_d2i(
    const(X509_REVOKED)* x,
    int nid,
    int* crit,
    int* idx);
int X509_REVOKED_add1_ext_i2d(
    X509_REVOKED* x,
    int nid,
    void* value,
    int crit,
    c_ulong flags);

X509_EXTENSION* X509_EXTENSION_create_by_NID(
    X509_EXTENSION** ex,
    int nid,
    int crit,
    ASN1_OCTET_STRING* data);
X509_EXTENSION* X509_EXTENSION_create_by_OBJ(
    X509_EXTENSION** ex,
    const(ASN1_OBJECT)* obj,
    int crit,
    ASN1_OCTET_STRING* data);
int X509_EXTENSION_set_object(X509_EXTENSION* ex, const(ASN1_OBJECT)* obj);
int X509_EXTENSION_set_critical(X509_EXTENSION* ex, int crit);
int X509_EXTENSION_set_data(X509_EXTENSION* ex, ASN1_OCTET_STRING* data);
ASN1_OBJECT* X509_EXTENSION_get_object(X509_EXTENSION* ex);
ASN1_OCTET_STRING* X509_EXTENSION_get_data(X509_EXTENSION* ne);
int X509_EXTENSION_get_critical(const(X509_EXTENSION)* ex);

int X509at_get_attr_count(const(stack_st_X509_ATTRIBUTE)* x);
int X509at_get_attr_by_NID(
    const(stack_st_X509_ATTRIBUTE)* x,
    int nid,
    int lastpos);
int X509at_get_attr_by_OBJ(
    const(stack_st_X509_ATTRIBUTE)* sk,
    const(ASN1_OBJECT)* obj,
    int lastpos);
X509_ATTRIBUTE* X509at_get_attr(const(stack_st_X509_ATTRIBUTE)* x, int loc);
X509_ATTRIBUTE* X509at_delete_attr(stack_st_X509_ATTRIBUTE* x, int loc);
stack_st_X509_ATTRIBUTE* X509at_add1_attr(
    stack_st_X509_ATTRIBUTE** x,
    X509_ATTRIBUTE* attr);
stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_OBJ(
    stack_st_X509_ATTRIBUTE** x,
    const(ASN1_OBJECT)* obj,
    int type,
    const(ubyte)* bytes,
    int len);
stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_NID(
    stack_st_X509_ATTRIBUTE** x,
    int nid,
    int type,
    const(ubyte)* bytes,
    int len);
stack_st_X509_ATTRIBUTE* X509at_add1_attr_by_txt(
    stack_st_X509_ATTRIBUTE** x,
    const(char)* attrname,
    int type,
    const(ubyte)* bytes,
    int len);
void* X509at_get0_data_by_OBJ(
    stack_st_X509_ATTRIBUTE* x,
    const(ASN1_OBJECT)* obj,
    int lastpos,
    int type);
X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_NID(
    X509_ATTRIBUTE** attr,
    int nid,
    int atrtype,
    const(void)* data,
    int len);
X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_OBJ(
    X509_ATTRIBUTE** attr,
    const(ASN1_OBJECT)* obj,
    int atrtype,
    const(void)* data,
    int len);
X509_ATTRIBUTE* X509_ATTRIBUTE_create_by_txt(
    X509_ATTRIBUTE** attr,
    const(char)* atrname,
    int type,
    const(ubyte)* bytes,
    int len);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE* attr, const(ASN1_OBJECT)* obj);
int X509_ATTRIBUTE_set1_data(
    X509_ATTRIBUTE* attr,
    int attrtype,
    const(void)* data,
    int len);
void* X509_ATTRIBUTE_get0_data(
    X509_ATTRIBUTE* attr,
    int idx,
    int atrtype,
    void* data);
int X509_ATTRIBUTE_count(const(X509_ATTRIBUTE)* attr);
ASN1_OBJECT* X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE* attr);
ASN1_TYPE* X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE* attr, int idx);

int EVP_PKEY_get_attr_count(const(EVP_PKEY)* key);
int EVP_PKEY_get_attr_by_NID(const(EVP_PKEY)* key, int nid, int lastpos);
int EVP_PKEY_get_attr_by_OBJ(
    const(EVP_PKEY)* key,
    const(ASN1_OBJECT)* obj,
    int lastpos);
X509_ATTRIBUTE* EVP_PKEY_get_attr(const(EVP_PKEY)* key, int loc);
X509_ATTRIBUTE* EVP_PKEY_delete_attr(EVP_PKEY* key, int loc);
int EVP_PKEY_add1_attr(EVP_PKEY* key, X509_ATTRIBUTE* attr);
int EVP_PKEY_add1_attr_by_OBJ(
    EVP_PKEY* key,
    const(ASN1_OBJECT)* obj,
    int type,
    const(ubyte)* bytes,
    int len);
int EVP_PKEY_add1_attr_by_NID(
    EVP_PKEY* key,
    int nid,
    int type,
    const(ubyte)* bytes,
    int len);
int EVP_PKEY_add1_attr_by_txt(
    EVP_PKEY* key,
    const(char)* attrname,
    int type,
    const(ubyte)* bytes,
    int len);

int X509_verify_cert(X509_STORE_CTX* ctx);

/* lookup a cert from a X509 STACK */
X509* X509_find_by_issuer_and_serial(
    stack_st_X509* sk,
    X509_NAME* name,
    ASN1_INTEGER* serial);
X509* X509_find_by_subject(stack_st_X509* sk, X509_NAME* name);

PBEPARAM* PBEPARAM_new();
void PBEPARAM_free(PBEPARAM* a);
PBEPARAM* d2i_PBEPARAM(PBEPARAM** a, const(ubyte*)* in_, c_long len);
int i2d_PBEPARAM(PBEPARAM* a, ubyte** out_);
extern __gshared const ASN1_ITEM PBEPARAM_it;
PBE2PARAM* PBE2PARAM_new();
void PBE2PARAM_free(PBE2PARAM* a);
PBE2PARAM* d2i_PBE2PARAM(PBE2PARAM** a, const(ubyte*)* in_, c_long len);
int i2d_PBE2PARAM(PBE2PARAM* a, ubyte** out_);
extern __gshared const ASN1_ITEM PBE2PARAM_it;
PBKDF2PARAM* PBKDF2PARAM_new();
void PBKDF2PARAM_free(PBKDF2PARAM* a);
PBKDF2PARAM* d2i_PBKDF2PARAM(PBKDF2PARAM** a, const(ubyte*)* in_, c_long len);
int i2d_PBKDF2PARAM(PBKDF2PARAM* a, ubyte** out_);
extern __gshared const ASN1_ITEM PBKDF2PARAM_it;

int PKCS5_pbe_set0_algor(
    X509_ALGOR* algor,
    int alg,
    int iter,
    const(ubyte)* salt,
    int saltlen);

X509_ALGOR* PKCS5_pbe_set(int alg, int iter, const(ubyte)* salt, int saltlen);
X509_ALGOR* PKCS5_pbe2_set(
    const(EVP_CIPHER)* cipher,
    int iter,
    ubyte* salt,
    int saltlen);
X509_ALGOR* PKCS5_pbe2_set_iv(
    const(EVP_CIPHER)* cipher,
    int iter,
    ubyte* salt,
    int saltlen,
    ubyte* aiv,
    int prf_nid);

version(OPENSSL_NO_SCRYPT) {} else {
X509_ALGOR* PKCS5_pbe2_set_scrypt(
    const(EVP_CIPHER)* cipher,
    const(ubyte)* salt,
    int saltlen,
    ubyte* aiv,
    ulong N,
    ulong r,
    ulong p);
}

X509_ALGOR* PKCS5_pbkdf2_set(
    int iter,
    ubyte* salt,
    int saltlen,
    int prf_nid,
    int keylen);

/* PKCS#8 utilities */

PKCS8_PRIV_KEY_INFO* PKCS8_PRIV_KEY_INFO_new();
void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO* a);
PKCS8_PRIV_KEY_INFO* d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO** a, const(ubyte*)* in_, c_long len);
int i2d_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO* a, ubyte** out_);
extern __gshared const ASN1_ITEM PKCS8_PRIV_KEY_INFO_it;

EVP_PKEY* EVP_PKCS82PKEY(const(PKCS8_PRIV_KEY_INFO)* p8);
PKCS8_PRIV_KEY_INFO* EVP_PKEY2PKCS8(EVP_PKEY* pkey);

int PKCS8_pkey_set0(
    PKCS8_PRIV_KEY_INFO* priv,
    ASN1_OBJECT* aobj,
    int version_,
    int ptype,
    void* pval,
    ubyte* penc,
    int penclen);
int PKCS8_pkey_get0(
    const(ASN1_OBJECT*)* ppkalg,
    const(ubyte*)* pk,
    int* ppklen,
    const(X509_ALGOR*)* pa,
    const(PKCS8_PRIV_KEY_INFO)* p8);

const(stack_st_X509_ATTRIBUTE)* PKCS8_pkey_get0_attrs(
    const(PKCS8_PRIV_KEY_INFO)* p8);
int PKCS8_pkey_add1_attr_by_NID(
    PKCS8_PRIV_KEY_INFO* p8,
    int nid,
    int type,
    const(ubyte)* bytes,
    int len);

int X509_PUBKEY_set0_param(
    X509_PUBKEY* pub,
    ASN1_OBJECT* aobj,
    int ptype,
    void* pval,
    ubyte* penc,
    int penclen);
int X509_PUBKEY_get0_param(
    ASN1_OBJECT** ppkalg,
    const(ubyte*)* pk,
    int* ppklen,
    X509_ALGOR** pa,
    X509_PUBKEY* pub);

int X509_check_trust(X509* x, int id, int flags);
int X509_TRUST_get_count();
X509_TRUST* X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_TRUST_add(
    int id,
    int flags,
    int function(X509_TRUST*, X509*, int) ck,
    const(char)* name,
    int arg1,
    void* arg2);
void X509_TRUST_cleanup();
int X509_TRUST_get_flags(const(X509_TRUST)* xp);
char* X509_TRUST_get0_name(const(X509_TRUST)* xp);
int X509_TRUST_get_trust(const(X509_TRUST)* xp);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_X509_strings();

/* Error codes for the X509 functions. */

/* Function codes. */
enum X509_F_ADD_CERT_DIR = 100;
enum X509_F_BUILD_CHAIN = 106;
enum X509_F_BY_FILE_CTRL = 101;
enum X509_F_CHECK_NAME_CONSTRAINTS = 149;
enum X509_F_CHECK_POLICY = 145;
enum X509_F_DANE_I2D = 107;
enum X509_F_DIR_CTRL = 102;
enum X509_F_GET_CERT_BY_SUBJECT = 103;
enum X509_F_NETSCAPE_SPKI_B64_DECODE = 129;
enum X509_F_NETSCAPE_SPKI_B64_ENCODE = 130;
enum X509_F_X509AT_ADD1_ATTR = 135;
enum X509_F_X509V3_ADD_EXT = 104;
enum X509_F_X509_ATTRIBUTE_CREATE_BY_NID = 136;
enum X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ = 137;
enum X509_F_X509_ATTRIBUTE_CREATE_BY_TXT = 140;
enum X509_F_X509_ATTRIBUTE_GET0_DATA = 139;
enum X509_F_X509_ATTRIBUTE_SET1_DATA = 138;
enum X509_F_X509_CHECK_PRIVATE_KEY = 128;
enum X509_F_X509_CRL_DIFF = 105;
enum X509_F_X509_CRL_PRINT_FP = 147;
enum X509_F_X509_EXTENSION_CREATE_BY_NID = 108;
enum X509_F_X509_EXTENSION_CREATE_BY_OBJ = 109;
enum X509_F_X509_GET_PUBKEY_PARAMETERS = 110;
enum X509_F_X509_LOAD_CERT_CRL_FILE = 132;
enum X509_F_X509_LOAD_CERT_FILE = 111;
enum X509_F_X509_LOAD_CRL_FILE = 112;
enum X509_F_X509_NAME_ADD_ENTRY = 113;
enum X509_F_X509_NAME_ENTRY_CREATE_BY_NID = 114;
enum X509_F_X509_NAME_ENTRY_CREATE_BY_TXT = 131;
enum X509_F_X509_NAME_ENTRY_SET_OBJECT = 115;
enum X509_F_X509_NAME_ONELINE = 116;
enum X509_F_X509_NAME_PRINT = 117;
enum X509_F_X509_OBJECT_NEW = 150;
enum X509_F_X509_PRINT_EX_FP = 118;
enum X509_F_X509_PUBKEY_DECODE = 148;
enum X509_F_X509_PUBKEY_GET0 = 119;
enum X509_F_X509_PUBKEY_SET = 120;
enum X509_F_X509_REQ_CHECK_PRIVATE_KEY = 144;
enum X509_F_X509_REQ_PRINT_EX = 121;
enum X509_F_X509_REQ_PRINT_FP = 122;
enum X509_F_X509_REQ_TO_X509 = 123;
enum X509_F_X509_STORE_ADD_CERT = 124;
enum X509_F_X509_STORE_ADD_CRL = 125;
enum X509_F_X509_STORE_CTX_GET1_ISSUER = 146;
enum X509_F_X509_STORE_CTX_INIT = 143;
enum X509_F_X509_STORE_CTX_NEW = 142;
enum X509_F_X509_STORE_CTX_PURPOSE_INHERIT = 134;
enum X509_F_X509_TO_X509_REQ = 126;
enum X509_F_X509_TRUST_ADD = 133;
enum X509_F_X509_TRUST_SET = 141;
enum X509_F_X509_VERIFY_CERT = 127;

/* Reason codes. */
enum X509_R_AKID_MISMATCH = 110;
enum X509_R_BAD_SELECTOR = 133;
enum X509_R_BAD_X509_FILETYPE = 100;
enum X509_R_BASE64_DECODE_ERROR = 118;
enum X509_R_CANT_CHECK_DH_KEY = 114;
enum X509_R_CERT_ALREADY_IN_HASH_TABLE = 101;
enum X509_R_CRL_ALREADY_DELTA = 127;
enum X509_R_CRL_VERIFY_FAILURE = 131;
enum X509_R_IDP_MISMATCH = 128;
enum X509_R_INVALID_DIRECTORY = 113;
enum X509_R_INVALID_FIELD_NAME = 119;
enum X509_R_INVALID_TRUST = 123;
enum X509_R_ISSUER_MISMATCH = 129;
enum X509_R_KEY_TYPE_MISMATCH = 115;
enum X509_R_KEY_VALUES_MISMATCH = 116;
enum X509_R_LOADING_CERT_DIR = 103;
enum X509_R_LOADING_DEFAULTS = 104;
enum X509_R_METHOD_NOT_SUPPORTED = 124;
enum X509_R_NAME_TOO_LONG = 134;
enum X509_R_NEWER_CRL_NOT_NEWER = 132;
enum X509_R_NO_CERT_SET_FOR_US_TO_VERIFY = 105;
enum X509_R_NO_CRL_NUMBER = 130;
enum X509_R_PUBLIC_KEY_DECODE_ERROR = 125;
enum X509_R_PUBLIC_KEY_ENCODE_ERROR = 126;
enum X509_R_SHOULD_RETRY = 106;
enum X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN = 107;
enum X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY = 108;
enum X509_R_UNKNOWN_KEY_TYPE = 117;
enum X509_R_UNKNOWN_NID = 109;
enum X509_R_UNKNOWN_PURPOSE_ID = 121;
enum X509_R_UNKNOWN_TRUST_ID = 120;
enum X509_R_UNSUPPORTED_ALGORITHM = 111;
enum X509_R_WRONG_LOOKUP_TYPE = 112;
enum X509_R_WRONG_TYPE = 122;

