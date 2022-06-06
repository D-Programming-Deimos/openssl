/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.x509_vfy;

import core.stdc.time;

import deimos.openssl._d_util;
import deimos.openssl.asn1:ASN1_OBJECT, stack_st_ASN1_OBJECT;

public import deimos.openssl.opensslconf;
public import deimos.openssl.lhash;
public import deimos.openssl.bio;
public import deimos.openssl.crypto;
public import deimos.openssl.symhacks;

extern (C):
nothrow:

/*
 * Protect against recursion, x509.h and x509_vfy.h each include the other.
 */

/*-
SSL_CTX -> X509_STORE
                -> X509_LOOKUP
                        ->X509_LOOKUP_METHOD
                -> X509_LOOKUP
                        ->X509_LOOKUP_METHOD

SSL     -> X509_STORE_CTX
                ->X509_STORE

The X509_STORE holds the tables etc for verification stuff.
A X509_STORE_CTX is used while validating a single certificate.
The X509_STORE has X509_LOOKUPs for looking up certs.
The X509_STORE then calls a function to actually verify the
certificate chain.
*/

enum X509_LOOKUP_TYPE
{
    X509_LU_NONE = 0,
    X509_LU_X509 = 1,
    X509_LU_CRL = 2
}

enum X509_LU_RETRY = -1;
enum X509_LU_FAIL = 0;

struct stack_st_X509_LOOKUP;
alias sk_X509_LOOKUP_compfunc = int function(const(X509_LOOKUP*)* a, const(X509_LOOKUP*)* b);
alias sk_X509_LOOKUP_freefunc = void function(X509_LOOKUP* a);
alias sk_X509_LOOKUP_copyfunc = x509_lookup_st* function(const(X509_LOOKUP)* a);
int sk_X509_LOOKUP_num(const(stack_st_X509_LOOKUP)* sk);
X509_LOOKUP* sk_X509_LOOKUP_value(const(stack_st_X509_LOOKUP)* sk, int idx);
stack_st_X509_LOOKUP* sk_X509_LOOKUP_new(sk_X509_LOOKUP_compfunc compare);
stack_st_X509_LOOKUP* sk_X509_LOOKUP_new_null();
void sk_X509_LOOKUP_free(stack_st_X509_LOOKUP* sk);
void sk_X509_LOOKUP_zero(stack_st_X509_LOOKUP* sk);
X509_LOOKUP* sk_X509_LOOKUP_delete(stack_st_X509_LOOKUP* sk, int i);
X509_LOOKUP* sk_X509_LOOKUP_delete_ptr(stack_st_X509_LOOKUP* sk, X509_LOOKUP* ptr);
int sk_X509_LOOKUP_push(stack_st_X509_LOOKUP* sk, X509_LOOKUP* ptr);
int sk_X509_LOOKUP_unshift(stack_st_X509_LOOKUP* sk, X509_LOOKUP* ptr);
X509_LOOKUP* sk_X509_LOOKUP_pop(stack_st_X509_LOOKUP* sk);
X509_LOOKUP* sk_X509_LOOKUP_shift(stack_st_X509_LOOKUP* sk);
void sk_X509_LOOKUP_pop_free(stack_st_X509_LOOKUP* sk, sk_X509_LOOKUP_freefunc freefunc);
int sk_X509_LOOKUP_insert(stack_st_X509_LOOKUP* sk, X509_LOOKUP* ptr, int idx);
X509_LOOKUP* sk_X509_LOOKUP_set(stack_st_X509_LOOKUP* sk, int idx, X509_LOOKUP* ptr);
int sk_X509_LOOKUP_find(stack_st_X509_LOOKUP* sk, X509_LOOKUP* ptr);
int sk_X509_LOOKUP_find_ex(stack_st_X509_LOOKUP* sk, X509_LOOKUP* ptr);
void sk_X509_LOOKUP_sort(stack_st_X509_LOOKUP* sk);
int sk_X509_LOOKUP_is_sorted(const(stack_st_X509_LOOKUP)* sk);
stack_st_X509_LOOKUP* sk_X509_LOOKUP_dup(const(stack_st_X509_LOOKUP)* sk);
stack_st_X509_LOOKUP* sk_X509_LOOKUP_deep_copy(const(stack_st_X509_LOOKUP)* sk, sk_X509_LOOKUP_copyfunc copyfunc, sk_X509_LOOKUP_freefunc freefunc);
sk_X509_LOOKUP_compfunc sk_X509_LOOKUP_set_cmp_func(stack_st_X509_LOOKUP* sk, sk_X509_LOOKUP_compfunc compare);
struct stack_st_X509_OBJECT;
alias sk_X509_OBJECT_compfunc = int function(const(X509_OBJECT*)* a, const(X509_OBJECT*)* b);
alias sk_X509_OBJECT_freefunc = void function(X509_OBJECT* a);
alias sk_X509_OBJECT_copyfunc = x509_object_st* function(const(X509_OBJECT)* a);
int sk_X509_OBJECT_num(const(stack_st_X509_OBJECT)* sk);
X509_OBJECT* sk_X509_OBJECT_value(const(stack_st_X509_OBJECT)* sk, int idx);
stack_st_X509_OBJECT* sk_X509_OBJECT_new(sk_X509_OBJECT_compfunc compare);
stack_st_X509_OBJECT* sk_X509_OBJECT_new_null();
void sk_X509_OBJECT_free(stack_st_X509_OBJECT* sk);
void sk_X509_OBJECT_zero(stack_st_X509_OBJECT* sk);
X509_OBJECT* sk_X509_OBJECT_delete(stack_st_X509_OBJECT* sk, int i);
X509_OBJECT* sk_X509_OBJECT_delete_ptr(stack_st_X509_OBJECT* sk, X509_OBJECT* ptr);
int sk_X509_OBJECT_push(stack_st_X509_OBJECT* sk, X509_OBJECT* ptr);
int sk_X509_OBJECT_unshift(stack_st_X509_OBJECT* sk, X509_OBJECT* ptr);
X509_OBJECT* sk_X509_OBJECT_pop(stack_st_X509_OBJECT* sk);
X509_OBJECT* sk_X509_OBJECT_shift(stack_st_X509_OBJECT* sk);
void sk_X509_OBJECT_pop_free(stack_st_X509_OBJECT* sk, sk_X509_OBJECT_freefunc freefunc);
int sk_X509_OBJECT_insert(stack_st_X509_OBJECT* sk, X509_OBJECT* ptr, int idx);
X509_OBJECT* sk_X509_OBJECT_set(stack_st_X509_OBJECT* sk, int idx, X509_OBJECT* ptr);
int sk_X509_OBJECT_find(stack_st_X509_OBJECT* sk, X509_OBJECT* ptr);
int sk_X509_OBJECT_find_ex(stack_st_X509_OBJECT* sk, X509_OBJECT* ptr);
void sk_X509_OBJECT_sort(stack_st_X509_OBJECT* sk);
int sk_X509_OBJECT_is_sorted(const(stack_st_X509_OBJECT)* sk);
stack_st_X509_OBJECT* sk_X509_OBJECT_dup(const(stack_st_X509_OBJECT)* sk);
stack_st_X509_OBJECT* sk_X509_OBJECT_deep_copy(const(stack_st_X509_OBJECT)* sk, sk_X509_OBJECT_copyfunc copyfunc, sk_X509_OBJECT_freefunc freefunc);
sk_X509_OBJECT_compfunc sk_X509_OBJECT_set_cmp_func(stack_st_X509_OBJECT* sk, sk_X509_OBJECT_compfunc compare);
struct stack_st_X509_VERIFY_PARAM;
alias sk_X509_VERIFY_PARAM_compfunc = int function(const(X509_VERIFY_PARAM*)* a, const(X509_VERIFY_PARAM*)* b);
alias sk_X509_VERIFY_PARAM_freefunc = void function(X509_VERIFY_PARAM* a);
alias sk_X509_VERIFY_PARAM_copyfunc = X509_VERIFY_PARAM_st* function(const(X509_VERIFY_PARAM)* a);
int sk_X509_VERIFY_PARAM_num(const(stack_st_X509_VERIFY_PARAM)* sk);
X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_value(const(stack_st_X509_VERIFY_PARAM)* sk, int idx);
stack_st_X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_new(sk_X509_VERIFY_PARAM_compfunc compare);
stack_st_X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_new_null();
void sk_X509_VERIFY_PARAM_free(stack_st_X509_VERIFY_PARAM* sk);
void sk_X509_VERIFY_PARAM_zero(stack_st_X509_VERIFY_PARAM* sk);
X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_delete(stack_st_X509_VERIFY_PARAM* sk, int i);
X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_delete_ptr(stack_st_X509_VERIFY_PARAM* sk, X509_VERIFY_PARAM* ptr);
int sk_X509_VERIFY_PARAM_push(stack_st_X509_VERIFY_PARAM* sk, X509_VERIFY_PARAM* ptr);
int sk_X509_VERIFY_PARAM_unshift(stack_st_X509_VERIFY_PARAM* sk, X509_VERIFY_PARAM* ptr);
X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_pop(stack_st_X509_VERIFY_PARAM* sk);
X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_shift(stack_st_X509_VERIFY_PARAM* sk);
void sk_X509_VERIFY_PARAM_pop_free(stack_st_X509_VERIFY_PARAM* sk, sk_X509_VERIFY_PARAM_freefunc freefunc);
int sk_X509_VERIFY_PARAM_insert(stack_st_X509_VERIFY_PARAM* sk, X509_VERIFY_PARAM* ptr, int idx);
X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_set(stack_st_X509_VERIFY_PARAM* sk, int idx, X509_VERIFY_PARAM* ptr);
int sk_X509_VERIFY_PARAM_find(stack_st_X509_VERIFY_PARAM* sk, X509_VERIFY_PARAM* ptr);
int sk_X509_VERIFY_PARAM_find_ex(stack_st_X509_VERIFY_PARAM* sk, X509_VERIFY_PARAM* ptr);
void sk_X509_VERIFY_PARAM_sort(stack_st_X509_VERIFY_PARAM* sk);
int sk_X509_VERIFY_PARAM_is_sorted(const(stack_st_X509_VERIFY_PARAM)* sk);
stack_st_X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_dup(const(stack_st_X509_VERIFY_PARAM)* sk);
stack_st_X509_VERIFY_PARAM* sk_X509_VERIFY_PARAM_deep_copy(const(stack_st_X509_VERIFY_PARAM)* sk, sk_X509_VERIFY_PARAM_copyfunc copyfunc, sk_X509_VERIFY_PARAM_freefunc freefunc);
sk_X509_VERIFY_PARAM_compfunc sk_X509_VERIFY_PARAM_set_cmp_func(stack_st_X509_VERIFY_PARAM* sk, sk_X509_VERIFY_PARAM_compfunc compare);

int X509_STORE_set_depth(X509_STORE* store, int depth);

alias X509_STORE_CTX_verify_cb = int function(int, X509_STORE_CTX*);
alias X509_STORE_CTX_verify_fn = int function(X509_STORE_CTX*);
alias X509_STORE_CTX_get_issuer_fn = int function(
    X509** issuer,
    X509_STORE_CTX* ctx,
    X509* x);
alias X509_STORE_CTX_check_issued_fn = int function(
    X509_STORE_CTX* ctx,
    X509* x,
    X509* issuer);
alias X509_STORE_CTX_check_revocation_fn = int function(X509_STORE_CTX* ctx);
alias X509_STORE_CTX_get_crl_fn = int function(
    X509_STORE_CTX* ctx,
    X509_CRL** crl,
    X509* x);
alias X509_STORE_CTX_check_crl_fn = int function(X509_STORE_CTX* ctx, X509_CRL* crl);
alias X509_STORE_CTX_cert_crl_fn = int function(
    X509_STORE_CTX* ctx,
    X509_CRL* crl,
    X509* x);
alias X509_STORE_CTX_check_policy_fn = int function(X509_STORE_CTX* ctx);

struct stack_st_X509;
alias X509_STORE_CTX_lookup_certs_fn = stack_st_X509* function(
    X509_STORE_CTX* ctx,
    X509_NAME* nm);

/* These are 'informational' when looking for issuer cert */

struct stack_st_X509_CRL;
alias X509_STORE_CTX_lookup_crls_fn = stack_st_X509_CRL* function(
    X509_STORE_CTX* ctx,
    X509_NAME* nm);
alias X509_STORE_CTX_cleanup_fn = int function(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_depth(X509_STORE_CTX* ctx, int depth);

extern (D) auto X509_STORE_CTX_set_app_data(T0, T1)(auto ref T0 ctx, auto ref T1 data)
{
    return X509_STORE_CTX_set_ex_data(ctx, 0, data);
}

extern (D) auto X509_STORE_CTX_get_app_data(T)(auto ref T ctx)
{
    return X509_STORE_CTX_get_ex_data(ctx, 0);
}

enum X509_L_FILE_LOAD = 1;
enum X509_L_ADD_DIR = 2;

extern (D) auto X509_LOOKUP_load_file(T0, T1, T2)(auto ref T0 x, auto ref T1 name, auto ref T2 type)
{
    return X509_LOOKUP_ctrl(x, X509_L_FILE_LOAD, name, cast(c_long) type, NULL);
}

extern (D) auto X509_LOOKUP_add_dir(T0, T1, T2)(auto ref T0 x, auto ref T1 name, auto ref T2 type)
{
    return X509_LOOKUP_ctrl(x, X509_L_ADD_DIR, name, cast(c_long) type, NULL);
}

enum X509_V_OK = 0;
enum X509_V_ERR_UNSPECIFIED = 1;
enum X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
enum X509_V_ERR_UNABLE_TO_GET_CRL = 3;
enum X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;
enum X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;
enum X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;
enum X509_V_ERR_CERT_SIGNATURE_FAILURE = 7;
enum X509_V_ERR_CRL_SIGNATURE_FAILURE = 8;
enum X509_V_ERR_CERT_NOT_YET_VALID = 9;
enum X509_V_ERR_CERT_HAS_EXPIRED = 10;
enum X509_V_ERR_CRL_NOT_YET_VALID = 11;
enum X509_V_ERR_CRL_HAS_EXPIRED = 12;
enum X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;
enum X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;
enum X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;
enum X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;
enum X509_V_ERR_OUT_OF_MEM = 17;
enum X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
enum X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
enum X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
enum X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;
enum X509_V_ERR_CERT_CHAIN_TOO_LONG = 22;
enum X509_V_ERR_CERT_REVOKED = 23;
enum X509_V_ERR_INVALID_CA = 24;
enum X509_V_ERR_PATH_LENGTH_EXCEEDED = 25;
enum X509_V_ERR_INVALID_PURPOSE = 26;
enum X509_V_ERR_CERT_UNTRUSTED = 27;
enum X509_V_ERR_CERT_REJECTED = 28;
enum X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29;
enum X509_V_ERR_AKID_SKID_MISMATCH = 30;
enum X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
enum X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32;
enum X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
enum X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
enum X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35;
enum X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;
enum X509_V_ERR_INVALID_NON_CA = 37;
enum X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38;
enum X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;
enum X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40;
enum X509_V_ERR_INVALID_EXTENSION = 41;
enum X509_V_ERR_INVALID_POLICY_EXTENSION = 42;
enum X509_V_ERR_NO_EXPLICIT_POLICY = 43;
enum X509_V_ERR_DIFFERENT_CRL_SCOPE = 44;
enum X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 45;
enum X509_V_ERR_UNNESTED_RESOURCE = 46;
enum X509_V_ERR_PERMITTED_VIOLATION = 47;
enum X509_V_ERR_EXCLUDED_VIOLATION = 48;
enum X509_V_ERR_SUBTREE_MINMAX = 49;
/* The application is not happy */
enum X509_V_ERR_APPLICATION_VERIFICATION = 50;
enum X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51;
enum X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52;
enum X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 53;
enum X509_V_ERR_CRL_PATH_VALIDATION_ERROR = 54;
/* Another issuer check debug option */
enum X509_V_ERR_PATH_LOOP = 55;
/* Suite B mode algorithm violation */
enum X509_V_ERR_SUITE_B_INVALID_VERSION = 56;
enum X509_V_ERR_SUITE_B_INVALID_ALGORITHM = 57;
enum X509_V_ERR_SUITE_B_INVALID_CURVE = 58;
enum X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM = 59;
enum X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED = 60;
enum X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61;
/* Host, email and IP check errors */
enum X509_V_ERR_HOSTNAME_MISMATCH = 62;
enum X509_V_ERR_EMAIL_MISMATCH = 63;
enum X509_V_ERR_IP_ADDRESS_MISMATCH = 64;
/* DANE TLSA errors */
enum X509_V_ERR_DANE_NO_MATCH = 65;
/* security level errors */
enum X509_V_ERR_EE_KEY_TOO_SMALL = 66;
enum X509_V_ERR_CA_KEY_TOO_SMALL = 67;
enum X509_V_ERR_CA_MD_TOO_WEAK = 68;
/* Caller error */
enum X509_V_ERR_INVALID_CALL = 69;
/* Issuer lookup error */
enum X509_V_ERR_STORE_LOOKUP = 70;
/* Certificate transparency */
enum X509_V_ERR_NO_VALID_SCTS = 71;

enum X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION = 72;

/* Certificate verify flags */

enum X509_V_FLAG_CB_ISSUER_CHECK = 0x0; /* Deprecated */

/* Use check time instead of current time */
enum X509_V_FLAG_USE_CHECK_TIME = 0x2;
/* Lookup CRLs */
enum X509_V_FLAG_CRL_CHECK = 0x4;
/* Lookup CRLs for whole chain */
enum X509_V_FLAG_CRL_CHECK_ALL = 0x8;
/* Ignore unhandled critical extensions */
enum X509_V_FLAG_IGNORE_CRITICAL = 0x10;
/* Disable workarounds for broken certificates */
enum X509_V_FLAG_X509_STRICT = 0x20;
/* Enable proxy certificate validation */
enum X509_V_FLAG_ALLOW_PROXY_CERTS = 0x40;
/* Enable policy checking */
enum X509_V_FLAG_POLICY_CHECK = 0x80;
/* Policy variable require-explicit-policy */
enum X509_V_FLAG_EXPLICIT_POLICY = 0x100;
/* Policy variable inhibit-any-policy */
enum X509_V_FLAG_INHIBIT_ANY = 0x200;
/* Policy variable inhibit-policy-mapping */
enum X509_V_FLAG_INHIBIT_MAP = 0x400;
/* Notify callback that policy is OK */
enum X509_V_FLAG_NOTIFY_POLICY = 0x800;
/* Extended CRL features such as indirect CRLs, alternate CRL signing keys */
enum X509_V_FLAG_EXTENDED_CRL_SUPPORT = 0x1000;
/* Delta CRL support */
enum X509_V_FLAG_USE_DELTAS = 0x2000;
/* Check self-signed CA signature */
enum X509_V_FLAG_CHECK_SS_SIGNATURE = 0x4000;
/* Use trusted store first */
enum X509_V_FLAG_TRUSTED_FIRST = 0x8000;
/* Suite B 128 bit only mode: not normally used */
enum X509_V_FLAG_SUITEB_128_LOS_ONLY = 0x10000;
/* Suite B 192 bit only mode */
enum X509_V_FLAG_SUITEB_192_LOS = 0x20000;
/* Suite B 128 bit mode allowing 192 bit algorithms */
enum X509_V_FLAG_SUITEB_128_LOS = 0x30000;
/* Allow partial chains if at least one certificate is in trusted store */
enum X509_V_FLAG_PARTIAL_CHAIN = 0x80000;
/*
 * If the initial chain is not trusted, do not attempt to build an alternative
 * chain. Alternate chain checking was introduced in 1.1.0. Setting this flag
 * will force the behaviour to match that of previous versions.
 */
enum X509_V_FLAG_NO_ALT_CHAINS = 0x100000;
/* Do not check certificate/CRL validity against current time */
enum X509_V_FLAG_NO_CHECK_TIME = 0x200000;

enum X509_VP_FLAG_DEFAULT = 0x1;
enum X509_VP_FLAG_OVERWRITE = 0x2;
enum X509_VP_FLAG_RESET_FLAGS = 0x4;
enum X509_VP_FLAG_LOCKED = 0x8;
enum X509_VP_FLAG_ONCE = 0x10;

/* Internal use: mask of policy related options */
enum X509_V_FLAG_POLICY_MASK = X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY | X509_V_FLAG_INHIBIT_ANY | X509_V_FLAG_INHIBIT_MAP;

int X509_OBJECT_idx_by_subject(
    stack_st_X509_OBJECT* h,
    X509_LOOKUP_TYPE type,
    X509_NAME* name);
X509_OBJECT* X509_OBJECT_retrieve_by_subject(
    stack_st_X509_OBJECT* h,
    X509_LOOKUP_TYPE type,
    X509_NAME* name);
X509_OBJECT* X509_OBJECT_retrieve_match(
    stack_st_X509_OBJECT* h,
    X509_OBJECT* x);
int X509_OBJECT_up_ref_count(X509_OBJECT* a);
X509_OBJECT* X509_OBJECT_new();
void X509_OBJECT_free(X509_OBJECT* a);
X509_LOOKUP_TYPE X509_OBJECT_get_type(const(X509_OBJECT)* a);
X509* X509_OBJECT_get0_X509(const(X509_OBJECT)* a);
X509_CRL* X509_OBJECT_get0_X509_CRL(X509_OBJECT* a);
X509_STORE* X509_STORE_new();
void X509_STORE_free(X509_STORE* v);
int X509_STORE_lock(X509_STORE* ctx);
int X509_STORE_unlock(X509_STORE* ctx);
int X509_STORE_up_ref(X509_STORE* v);
stack_st_X509_OBJECT* X509_STORE_get0_objects(X509_STORE* v);

stack_st_X509* X509_STORE_CTX_get1_certs(X509_STORE_CTX* st, X509_NAME* nm);
stack_st_X509_CRL* X509_STORE_CTX_get1_crls(X509_STORE_CTX* st, X509_NAME* nm);
int X509_STORE_set_flags(X509_STORE* ctx, c_ulong flags);
int X509_STORE_set_purpose(X509_STORE* ctx, int purpose);
int X509_STORE_set_trust(X509_STORE* ctx, int trust);
int X509_STORE_set1_param(X509_STORE* ctx, X509_VERIFY_PARAM* pm);
X509_VERIFY_PARAM* X509_STORE_get0_param(X509_STORE* ctx);

void X509_STORE_set_verify(X509_STORE* ctx, X509_STORE_CTX_verify_fn verify);
alias X509_STORE_set_verify_func = X509_STORE_set_verify;
void X509_STORE_CTX_set_verify(
    X509_STORE_CTX* ctx,
    X509_STORE_CTX_verify_fn verify);
X509_STORE_CTX_verify_fn X509_STORE_get_verify(X509_STORE* ctx);
void X509_STORE_set_verify_cb(
    X509_STORE* ctx,
    X509_STORE_CTX_verify_cb verify_cb);
alias X509_STORE_set_verify_cb_func = X509_STORE_set_verify_cb;
X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(X509_STORE* ctx);
void X509_STORE_set_get_issuer(
    X509_STORE* ctx,
    X509_STORE_CTX_get_issuer_fn get_issuer);
X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(X509_STORE* ctx);
void X509_STORE_set_check_issued(
    X509_STORE* ctx,
    X509_STORE_CTX_check_issued_fn check_issued);
X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(X509_STORE* ctx);
void X509_STORE_set_check_revocation(
    X509_STORE* ctx,
    X509_STORE_CTX_check_revocation_fn check_revocation);
X509_STORE_CTX_check_revocation_fn X509_STORE_get_check_revocation(X509_STORE* ctx);
void X509_STORE_set_get_crl(X509_STORE* ctx, X509_STORE_CTX_get_crl_fn get_crl);
X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(X509_STORE* ctx);
void X509_STORE_set_check_crl(
    X509_STORE* ctx,
    X509_STORE_CTX_check_crl_fn check_crl);
X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(X509_STORE* ctx);
void X509_STORE_set_cert_crl(
    X509_STORE* ctx,
    X509_STORE_CTX_cert_crl_fn cert_crl);
X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(X509_STORE* ctx);
void X509_STORE_set_check_policy(
    X509_STORE* ctx,
    X509_STORE_CTX_check_policy_fn check_policy);
X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(X509_STORE* ctx);
void X509_STORE_set_lookup_certs(
    X509_STORE* ctx,
    X509_STORE_CTX_lookup_certs_fn lookup_certs);
X509_STORE_CTX_lookup_certs_fn X509_STORE_get_lookup_certs(X509_STORE* ctx);
void X509_STORE_set_lookup_crls(
    X509_STORE* ctx,
    X509_STORE_CTX_lookup_crls_fn lookup_crls);
alias X509_STORE_set_lookup_crls_cb = X509_STORE_set_lookup_crls;
X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(X509_STORE* ctx);
void X509_STORE_set_cleanup(X509_STORE* ctx, X509_STORE_CTX_cleanup_fn cleanup);
X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(X509_STORE* ctx);

static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
	int X509_STORE_get_ex_new_index(long argl, void* argp, CRYPTO_EX_new* new_func,
		CRYPTO_EX_dup* dup_func, CRYPTO_EX_free* free_func);
}
else
{
	auto X509_STORE_get_ex_new_index () (long l, void* p, CRYPTO_EX_new* newf,
		CRYPTO_EX_dup* dupf, CRYPTO_EX_free* freef)
	{
		return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef);
	}
}


int X509_STORE_set_ex_data(X509_STORE* ctx, int idx, void* data);
void* X509_STORE_get_ex_data(X509_STORE* ctx, int idx);

X509_STORE_CTX* X509_STORE_CTX_new();

int X509_STORE_CTX_get1_issuer(X509** issuer, X509_STORE_CTX* ctx, X509* x);

void X509_STORE_CTX_free(X509_STORE_CTX* ctx);
int X509_STORE_CTX_init(
    X509_STORE_CTX* ctx,
    X509_STORE* store,
    X509* x509,
    stack_st_X509* chain);
void X509_STORE_CTX_set0_trusted_stack(X509_STORE_CTX* ctx, stack_st_X509* sk);
void X509_STORE_CTX_cleanup(X509_STORE_CTX* ctx);

X509_STORE* X509_STORE_CTX_get0_store(X509_STORE_CTX* ctx);
X509* X509_STORE_CTX_get0_cert(X509_STORE_CTX* ctx);
stack_st_X509* X509_STORE_CTX_get0_untrusted(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX* ctx, stack_st_X509* sk);
void X509_STORE_CTX_set_verify_cb(
    X509_STORE_CTX* ctx,
    X509_STORE_CTX_verify_cb verify);
X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(X509_STORE_CTX* ctx);
X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(X509_STORE_CTX* ctx);
X509_STORE_CTX_get_issuer_fn X509_STORE_CTX_get_get_issuer(X509_STORE_CTX* ctx);
X509_STORE_CTX_check_issued_fn X509_STORE_CTX_get_check_issued(X509_STORE_CTX* ctx);
X509_STORE_CTX_check_revocation_fn X509_STORE_CTX_get_check_revocation(X509_STORE_CTX* ctx);
X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(X509_STORE_CTX* ctx);
X509_STORE_CTX_check_crl_fn X509_STORE_CTX_get_check_crl(X509_STORE_CTX* ctx);
X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(X509_STORE_CTX* ctx);
X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(X509_STORE_CTX* ctx);
X509_STORE_CTX_lookup_certs_fn X509_STORE_CTX_get_lookup_certs(X509_STORE_CTX* ctx);
X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(X509_STORE_CTX* ctx);
X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(X509_STORE_CTX* ctx);

alias X509_STORE_CTX_get_chain = X509_STORE_CTX_get0_chain;
alias X509_STORE_CTX_set_chain = X509_STORE_CTX_set0_untrusted;
alias X509_STORE_CTX_trusted_stack = X509_STORE_CTX_set0_trusted_stack;
alias X509_STORE_get_by_subject = X509_STORE_CTX_get_by_subject;
alias X509_STORE_get1_cert = X509_STORE_CTX_get1_certs;
alias X509_STORE_get1_crl = X509_STORE_CTX_get1_crls;

X509_LOOKUP* X509_STORE_add_lookup(X509_STORE* v, X509_LOOKUP_METHOD* m);
X509_LOOKUP_METHOD* X509_LOOKUP_hash_dir();
X509_LOOKUP_METHOD* X509_LOOKUP_file();

int X509_STORE_add_cert(X509_STORE* ctx, X509* x);
int X509_STORE_add_crl(X509_STORE* ctx, X509_CRL* x);

int X509_STORE_CTX_get_by_subject(
    X509_STORE_CTX* vs,
    X509_LOOKUP_TYPE type,
    X509_NAME* name,
    X509_OBJECT* ret);
X509_OBJECT* X509_STORE_CTX_get_obj_by_subject(
    X509_STORE_CTX* vs,
    X509_LOOKUP_TYPE type,
    X509_NAME* name);

int X509_LOOKUP_ctrl(
    X509_LOOKUP* ctx,
    int cmd,
    const(char)* argc,
    c_long argl,
    char** ret);

int X509_load_cert_file(X509_LOOKUP* ctx, const(char)* file, int type);
int X509_load_crl_file(X509_LOOKUP* ctx, const(char)* file, int type);
int X509_load_cert_crl_file(X509_LOOKUP* ctx, const(char)* file, int type);

X509_LOOKUP* X509_LOOKUP_new(X509_LOOKUP_METHOD* method);
void X509_LOOKUP_free(X509_LOOKUP* ctx);
int X509_LOOKUP_init(X509_LOOKUP* ctx);
int X509_LOOKUP_by_subject(
    X509_LOOKUP* ctx,
    X509_LOOKUP_TYPE type,
    X509_NAME* name,
    X509_OBJECT* ret);
int X509_LOOKUP_by_issuer_serial(
    X509_LOOKUP* ctx,
    X509_LOOKUP_TYPE type,
    X509_NAME* name,
    ASN1_INTEGER* serial,
    X509_OBJECT* ret);
int X509_LOOKUP_by_fingerprint(
    X509_LOOKUP* ctx,
    X509_LOOKUP_TYPE type,
    const(ubyte)* bytes,
    int len,
    X509_OBJECT* ret);
int X509_LOOKUP_by_alias(
    X509_LOOKUP* ctx,
    X509_LOOKUP_TYPE type,
    const(char)* str,
    int len,
    X509_OBJECT* ret);
int X509_LOOKUP_shutdown(X509_LOOKUP* ctx);

int X509_STORE_load_locations(
    X509_STORE* ctx,
    const(char)* file,
    const(char)* dir);
int X509_STORE_set_default_paths(X509_STORE* ctx);

static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
	int X509_STORE_CTX_get_ex_new_index(long argl, void* argp, CRYPTO_EX_new* new_func,
		CRYPTO_EX_dup* dup_func, CRYPTO_EX_free* free_func);
}
else
{
	auto X509_STORE_CTX_get_ex_new_index () (long l, void* p, CRYPTO_EX_new* newf,
		CRYPTO_EX_dup* dupf, CRYPTO_EX_free* freef)
	{
		return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef);
	}
}

int X509_STORE_CTX_set_ex_data(X509_STORE_CTX* ctx, int idx, void* data);
void* X509_STORE_CTX_get_ex_data(X509_STORE_CTX* ctx, int idx);
int X509_STORE_CTX_get_error(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX* ctx, int s);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_error_depth(X509_STORE_CTX* ctx, int depth);
X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_current_cert(X509_STORE_CTX* ctx, X509* x);
X509* X509_STORE_CTX_get0_current_issuer(X509_STORE_CTX* ctx);
X509_CRL* X509_STORE_CTX_get0_current_crl(X509_STORE_CTX* ctx);
X509_STORE_CTX* X509_STORE_CTX_get0_parent_ctx(X509_STORE_CTX* ctx);
stack_st_X509* X509_STORE_CTX_get0_chain(X509_STORE_CTX* ctx);
stack_st_X509* X509_STORE_CTX_get1_chain(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX* c, X509* x);
void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX* c, stack_st_X509* sk);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX* c, stack_st_X509_CRL* sk);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX* ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX* ctx, int trust);
int X509_STORE_CTX_purpose_inherit(
    X509_STORE_CTX* ctx,
    int def_purpose,
    int purpose,
    int trust);
void X509_STORE_CTX_set_flags(X509_STORE_CTX* ctx, c_ulong flags);
void X509_STORE_CTX_set_time(X509_STORE_CTX* ctx, c_ulong flags, time_t t);

X509_POLICY_TREE* X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX* ctx);
int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX* ctx);
int X509_STORE_CTX_get_num_untrusted(X509_STORE_CTX* ctx);

X509_VERIFY_PARAM* X509_STORE_CTX_get0_param(X509_STORE_CTX* ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX* ctx, X509_VERIFY_PARAM* param);
int X509_STORE_CTX_set_default(X509_STORE_CTX* ctx, const(char)* name);

/*
 * Bridge opacity barrier between libcrypt and libssl, also needed to support
 * offline testing in test/danetest.c
 */
void X509_STORE_CTX_set0_dane(X509_STORE_CTX* ctx, SSL_DANE* dane);
enum DANE_FLAG_NO_DANE_EE_NAMECHECKS = 1L << 0;

/* X509_VERIFY_PARAM functions */

X509_VERIFY_PARAM* X509_VERIFY_PARAM_new();
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM* param);
int X509_VERIFY_PARAM_inherit(
    X509_VERIFY_PARAM* to,
    const(X509_VERIFY_PARAM)* from);
int X509_VERIFY_PARAM_set1(
    X509_VERIFY_PARAM* to,
    const(X509_VERIFY_PARAM)* from);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM* param, const(char)* name);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM* param, c_ulong flags);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM* param, c_ulong flags);
c_ulong X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM* param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM* param, int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM* param, int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM* param, int depth);
void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM* param, int auth_level);
time_t X509_VERIFY_PARAM_get_time(const(X509_VERIFY_PARAM)* param);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM* param, time_t t);
int X509_VERIFY_PARAM_add0_policy(
    X509_VERIFY_PARAM* param,
    ASN1_OBJECT* policy);
int X509_VERIFY_PARAM_set1_policies(
    X509_VERIFY_PARAM* param,
    stack_st_ASN1_OBJECT* policies);

int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM* param, uint flags);
uint X509_VERIFY_PARAM_get_inh_flags(const(X509_VERIFY_PARAM)* param);

int X509_VERIFY_PARAM_set1_host(
    X509_VERIFY_PARAM* param,
    const(char)* name,
    size_t namelen);
int X509_VERIFY_PARAM_add1_host(
    X509_VERIFY_PARAM* param,
    const(char)* name,
    size_t namelen);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM* param, uint flags);
char* X509_VERIFY_PARAM_get0_peername(X509_VERIFY_PARAM*);
void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM*, X509_VERIFY_PARAM*);
int X509_VERIFY_PARAM_set1_email(
    X509_VERIFY_PARAM* param,
    const(char)* email,
    size_t emaillen);
int X509_VERIFY_PARAM_set1_ip(
    X509_VERIFY_PARAM* param,
    const(ubyte)* ip,
    size_t iplen);
int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM* param, const(char)* ipasc);

int X509_VERIFY_PARAM_get_depth(const(X509_VERIFY_PARAM)* param);
int X509_VERIFY_PARAM_get_auth_level(const(X509_VERIFY_PARAM)* param);
const(char)* X509_VERIFY_PARAM_get0_name(const(X509_VERIFY_PARAM)* param);

int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM* param);
int X509_VERIFY_PARAM_get_count();
const(X509_VERIFY_PARAM)* X509_VERIFY_PARAM_get0(int id);
const(X509_VERIFY_PARAM)* X509_VERIFY_PARAM_lookup(const(char)* name);
void X509_VERIFY_PARAM_table_cleanup();

/* Non positive return values are errors */
enum X509_PCY_TREE_FAILURE = -2; /* Failure to satisfy explicit policy */
enum X509_PCY_TREE_INVALID = -1; /* Inconsistent or invalid extensions */
enum X509_PCY_TREE_INTERNAL = 0; /* Internal error, most likely malloc */

/*
 * Positive return values form a bit mask, all but the first are internal to
 * the library and don't appear in results from X509_policy_check().
 */
enum X509_PCY_TREE_VALID = 1; /* The policy tree is valid */
enum X509_PCY_TREE_EMPTY = 2; /* The policy tree is empty */
enum X509_PCY_TREE_EXPLICIT = 4; /* Explicit policy required */

int X509_policy_check(
    X509_POLICY_TREE** ptree,
    int* pexplicit_policy,
    stack_st_X509* certs,
    stack_st_ASN1_OBJECT* policy_oids,
    uint flags);

void X509_policy_tree_free(X509_POLICY_TREE* tree);

int X509_policy_tree_level_count(const(X509_POLICY_TREE)* tree);
X509_POLICY_LEVEL* X509_policy_tree_get0_level(
    const(X509_POLICY_TREE)* tree,
    int i);

struct stack_st_X509_POLICY_NODE;
stack_st_X509_POLICY_NODE* X509_policy_tree_get0_policies(
    const(X509_POLICY_TREE)* tree);

stack_st_X509_POLICY_NODE* X509_policy_tree_get0_user_policies(
    const(X509_POLICY_TREE)* tree);

int X509_policy_level_node_count(X509_POLICY_LEVEL* level);

X509_POLICY_NODE* X509_policy_level_get0_node(X509_POLICY_LEVEL* level, int i);

const(ASN1_OBJECT)* X509_policy_node_get0_policy(const(X509_POLICY_NODE)* node);

struct stack_st_POLICYQUALINFO;
stack_st_POLICYQUALINFO* X509_policy_node_get0_qualifiers(
    const(X509_POLICY_NODE)* node);
const(X509_POLICY_NODE)* X509_policy_node_get0_parent(
    const(X509_POLICY_NODE)* node);
