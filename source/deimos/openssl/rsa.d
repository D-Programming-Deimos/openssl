/**
 * Port of `openssl.rsa.h`
 *
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
module deimos.openssl.rsa;

import deimos.openssl._d_util;
import deimos.openssl.opensslv;

import deimos.openssl.evp; // Needed for EVP_PKEY_ALG_CTRL.

public import deimos.openssl.asn1;

version(OPENSSL_NO_BIO) {} else {
public import deimos.openssl.bio;
}
public import deimos.openssl.crypto;
public import deimos.openssl.types;
version(OPENSSL_NO_DEPRECATED) {} else {
public import deimos.openssl.bn;
}

version (OPENSSL_NO_RSA) {
  static assert(false, "RSA is disabled.");
}

extern (C):
nothrow:

// The following aliases are derived from the `RSA_meth_*` functions' signatures
// They are not present in the code, hence are `private`.
private alias RSA_enc_dec_fn = extern(C) int function(int flen,
	const(ubyte)* from, ubyte* to, RSA* rsa, int padding);
private alias RSA_modexp_fn = extern(C) int function(BIGNUM* r0,
	const(BIGNUM)* I, RSA* rsa, BN_CTX* ctx);
private alias RSA_bn_modexp_fn = extern(C) int function(BIGNUM* r,
	const(BIGNUM)* a, const(BIGNUM)* p, const(BIGNUM)* m, BN_CTX* ctx,
	BN_MONT_CTX* m_ctx);
private alias RSA_lifetime_fn = extern(C) int function(RSA* rsa);
private alias RSA_sign_fn = extern(C) int function(int type,
	const(ubyte)* m, uint m_length, ubyte* sigret, uint* siglen, const(RSA)* rsa);
private alias RSA_verify_fn = extern(C) int function(int dtype,
	const(ubyte)* m, uint m_length, const(ubyte)* sigret, uint* siglen,
	const(RSA)* rsa);
private alias RSA_keygen_fn = extern(C) int function(RSA* rsa,
	int bits, BIGNUM* e, BN_GENCB* cb);

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
	// https://github.com/openssl/openssl/commit/b72c9121379a5de0c8be0d4e1a4a6b9495042621

	RSA_METHOD* RSA_meth_new(const(char)* name, int flags);
	void RSA_meth_free(RSA_METHOD* meth);
	RSA_METHOD* RSA_meth_dup(const(RSA_METHOD)* meth);

	const(char)* RSA_meth_get0_name(const(RSA_METHOD)* meth);
	int RSA_meth_set1_name(RSA_METHOD* meth, const(char)* name);

	int RSA_meth_get_flags(RSA_METHOD* meth);
	int RSA_meth_set_flags(RSA_METHOD* meth, int flags);
	void* RSA_meth_get0_app_data(const(RSA_METHOD)* meth);
	int RSA_meth_set0_app_data(RSA_METHOD* meth, void *app_data);

	RSA_enc_dec_fn RSA_meth_get_pub_enc(const(RSA_METHOD)* meth);
	int RSA_meth_set_pub_enc(RSA_METHOD* rsa, RSA_enc_dec_fn pub_enc);
	RSA_enc_dec_fn RSA_meth_get_pub_dec(const(RSA_METHOD)* meth);
	int RSA_meth_set_pub_dec(RSA_METHOD* rsa, RSA_enc_dec_fn pub_dec);

	RSA_enc_dec_fn RSA_meth_get_priv_enc(const(RSA_METHOD)* meth);
	int RSA_meth_set_priv_enc(RSA_METHOD* rsa, RSA_enc_dec_fn priv_enc);
	RSA_enc_dec_fn RSA_meth_get_priv_dec(const(RSA_METHOD)* meth);
	int RSA_meth_set_priv_dec(RSA_METHOD* rsa, RSA_enc_dec_fn priv_dec);

	RSA_modexp_fn RSA_meth_get_mod_exp(const(RSA_METHOD)* meth);
	int RSA_meth_set_mod_exp(RSA_METHOD* rsa, RSA_modexp_fn mod_exp);

	RSA_bn_modexp_fn RSA_meth_get_bn_mod_exp(const(RSA_METHOD)* meth);
	int RSA_meth_set_bn_mod_exp(RSA_METHOD* rsa, RSA_bn_modexp_fn bn_mod_exp);

	RSA_lifetime_fn RSA_meth_get_init(const(RSA_METHOD)* meth);
	int RSA_meth_set_init(RSA_METHOD* rsa, RSA_lifetime_fn init);
	RSA_lifetime_fn RSA_meth_get_finish(const(RSA_METHOD)* meth);
	int RSA_meth_set_finish(RSA_METHOD* rsa, RSA_lifetime_fn finish);

	RSA_sign_fn RSA_meth_get_sign(const(RSA_METHOD)* meth);
	int RSA_meth_set_sign(RSA_METHOD* rsa, RSA_sign_fn sign);

	RSA_verify_fn RSA_meth_get_verify(const(RSA_METHOD)* meth);
	int RSA_meth_set_verify(RSA_METHOD* rsa, RSA_verify_fn verify);

	RSA_keygen_fn RSA_meth_get_keygen(const(RSA_METHOD)* meth);
	int RSA_meth_set_keygen(RSA_METHOD* rsa, RSA_keygen_fn keygen);
}
else
{
struct rsa_meth_st
{
	const(char)* name;
	RSA_enc_dec_fn rsa_pub_enc;
	RSA_enc_dec_fn rsa_pub_dec;
	RSA_enc_dec_fn rsa_priv_enc;
	RSA_enc_dec_fn rsa_priv_dec;
	RSA_modexp_fn rsa_mod_exp; /* Can be null */
	RSA_bn_modexp_fn bn_mod_exp; /* Can be null */
	RSA_lifetime_fn init_;		/* called at new */
	RSA_lifetime_fn finish;	/* called at free */
	int flags;			/* RSA_METHOD_FLAG_* things */
	char* app_data;			/* may be needed! */
/* New sign and verify functions: some libraries don't allow arbitrary data
 * to be signed/verified: this allows them to be used. Note: for this to work
 * the RSA_public_decrypt() and RSA_private_encrypt() should* NOT* be used
 * RSA_sign(), RSA_verify() should be used instead. Note: for backwards
 * compatibility this functionality is only enabled if the RSA_FLAG_SIGN_VER
 * option is set in 'flags'.
 */
	RSA_sign_fn rsa_sign;
	RSA_verify_fn rsa_verify;
/* If this callback is NULL, the builtin software RSA key-gen will be used. This
 * is for behavioural compatibility whilst the code gets rewired, but one day
 * it would be nice to assume there are no such things as "builtin software"
 * implementations. */
	RSA_keygen_fn rsa_keygen;
}
}

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
	// https://github.com/openssl/openssl/commit/9862e9aa98ee1e38fbcef8d1dd5db0e750eb5e8d
	int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
	int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
	int RSA_set0_crt_params(RSA *r,BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
	void RSA_get0_key(const RSA *r, BIGNUM **n, BIGNUM **e, BIGNUM **d);
	void RSA_get0_factors(const RSA *r, BIGNUM **p, BIGNUM **q);
	void RSA_get0_crt_params(const RSA *r,
							 BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp);
	void RSA_clear_flags(RSA *r, int flags);
	int RSA_test_flags(const RSA *r, int flags);
	void RSA_set_flags(RSA *r, int flags);
	ENGINE *RSA_get0_engine(RSA *r);
}
else
{
struct rsa_st
{
	/* The first parameter is used to pickup errors where
	 * this is passed instead of aEVP_PKEY, it is set to 0 */
	int pad;
	c_long version_;
	const(RSA_METHOD)* meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE* engine;
	BIGNUM* n;
	BIGNUM* e;
	BIGNUM* d;
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* dmp1;
	BIGNUM* dmq1;
	BIGNUM* iqmp;
	/* be careful using this if the RSA structure is shared */
	CRYPTO_EX_DATA ex_data;
	int references;
	int flags;

	/* Used to cache montgomery values */
	BN_MONT_CTX* _method_mod_n;
	BN_MONT_CTX* _method_mod_p;
	BN_MONT_CTX* _method_mod_q;

	/* all BIGNUM values are actually in the following data, if it is not
	 * NULL */
	char* bignum_data;
	BN_BLINDING* blinding;
	BN_BLINDING* mt_blinding;
}
}

// #ifndef OPENSSL_RSA_MAX_MODULUS_BITS
enum OPENSSL_RSA_MAX_MODULUS_BITS = 16384;
// #endif

// #ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
enum OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
// #endif
// #ifndef OPENSSL_RSA_MAX_PUBEXP_BITS
enum OPENSSL_RSA_MAX_PUBEXP_BITS = 64; /* exponent limit enforced for "large" modulus only */
// #endif

enum RSA_3 = 0x3;
enum RSA_F4 = 0x10001;

enum RSA_METHOD_FLAG_NO_CHECK = 0x0001; /* don't check pub/private match */

enum RSA_FLAG_CACHE_PUBLIC = 0x0002;
enum RSA_FLAG_CACHE_PRIVATE = 0x0004;
enum RSA_FLAG_BLINDING = 0x0008;
enum RSA_FLAG_THREAD_SAFE = 0x0010;
/* This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag bn_mod_exp
 * gets called when private key components are absent.
 */
enum RSA_FLAG_EXT_PKEY = 0x0020;

/* This flag in the RSA_METHOD enables the new rsa_sign, rsa_verify functions.
 */
enum RSA_FLAG_SIGN_VER = 0x0040;

enum RSA_FLAG_NO_BLINDING = 0x0080; /* new with 0.9.6j and 0.9.7b; the built-in
                                                * RSA implementation now uses blinding by
                                                * default (ignoring RSA_FLAG_BLINDING),
                                                * but other engines might not need it
                                                */
enum RSA_FLAG_NO_CONSTTIME = 0x0100; /* new with 0.9.8f; the built-in RSA
						* implementation now uses constant time
						* operations by default in private key operations,
						* e.g., constant time modular exponentiation,
                                                * modular inverse without leaking branches,
                                                * division without leaking branches. This
                                                * flag disables these constant time
                                                * operations and results in faster RSA
                                                * private key operations.
                                                */
version(OPENSSL_NO_DEPRECATED) {} else {
alias RSA_FLAG_NO_CONSTTIME RSA_FLAG_NO_EXP_CONSTTIME; /* deprecated name for the flag*/
                                                /* new with 0.9.7h; the built-in RSA
                                                * implementation now uses constant time
                                                * modular exponentiation for secret exponents
                                                * by default. This flag causes the
                                                * faster variable sliding window method to
                                                * be used for all exponents.
                                                */
}


auto EVP_PKEY_CTX_set_rsa_padding()(EVP_PKEY_CTX* ctx, int pad) {
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING,
				pad, null);
}

auto EVP_PKEY_CTX_get_rsa_padding()(EVP_PKEY_CTX* ctx, int *ppad) {
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, -1,
                                 EVP_PKEY_CTRL_GET_RSA_PADDING, 0, ppad);
}

auto EVP_PKEY_CTX_set_rsa_pss_saltlen()(EVP_PKEY_CTX* ctx, int len) {
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,
				(EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY),
				EVP_PKEY_CTRL_RSA_PSS_SALTLEN,
				len, null);
}

auto EVP_PKEY_CTX_get_rsa_pss_saltlen()(EVP_PKEY_CTX* ctx, int *plen) {
	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,
				(EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY),
				EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN,
                                 0, plen);
}

static if (OPENSSL_VERSION_AT_LEAST(3, 0, 0))
{
	// v3.0.0 deprecated `EVP_PKEY_CTX_set_rsa_keygen_pubexp` and introduced
	// a `[...]set1[...]` alternative:
	// https://github.com/openssl/openssl/commit/3786d74868fe440250f902ce1a78974136ca9304
	// This is for forward compatibility: Old code still works with new OpenSSL version
	alias EVP_PKEY_CTX_set_rsa_keygen_pubexp = EVP_PKEY_CTX_set1_rsa_keygen_pubexp;

	// Before v3.0.0, those functions were macros (including above deprecated one):
	// https://github.com/openssl/openssl/commit/2972af109e10c5ce30e548190e3eee28327d6043
	int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int bits);
	int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX* ctx, void* pubexp);
	int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX* ctx, int primes);
}
else
{
	// Forward compatibility alias: Code written for v3.0.0 works with v1.1.1 and below
	alias EVP_PKEY_CTX_set1_rsa_keygen_pubexp = EVP_PKEY_CTX_set_rsa_keygen_pubexp;

	auto EVP_PKEY_CTX_set_rsa_keygen_bits()(EVP_PKEY_CTX* ctx, int bits) {
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
								EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, null);
	}

	auto EVP_PKEY_CTX_set_rsa_keygen_pubexp()(EVP_PKEY_CTX* ctx, void* pubexp) {
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
								 EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp);
	}

	static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
	{
		// Multi-prime RSA (RFC 8017), introduced in v1.1.1:
		// https://github.com/openssl/openssl/commit/665d899fa6d3571da016925067ebcf1789d7d19c
		auto EVP_PKEY_CTX_set_rsa_keygen_primes()(EVP_PKEY_CTX* ctx, int primes) {
			return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN,
									 EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, primes, null);
		}
	}
}

auto EVP_PKEY_CTX_set_rsa_mgf1_md()(EVP_PKEY_CTX* ctx, EVP_MD* md) {
	static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
		enum ExtraFlags = EVP_PKEY_OP_TYPE_CRYPT;
	else
		enum ExtraFlags = 0;

	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_SIG | ExtraFlags,
							 EVP_PKEY_CTRL_RSA_MGF1_MD, 0, md);
}

auto EVP_PKEY_CTX_get_rsa_mgf1_md()(EVP_PKEY_CTX* ctx, EVP_MD** pmd) {
	static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
		enum ExtraFlags = EVP_PKEY_OP_TYPE_CRYPT;
	else
		enum ExtraFlags = 0;

	return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_SIG | ExtraFlags,
							 EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, pmd);
}

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
	auto EVP_PKEY_CTX_set_rsa_oaep_md()(EVP_PKEY_CTX* ctx, EVP_MD* md) {
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
								 EVP_PKEY_CTRL_RSA_OAEP_MD, 0, md);
	}

	auto EVP_PKEY_CTX_set0_rsa_oaep_label()(EVP_PKEY_CTX* ctx, ubyte* label, int len) {
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
								 EVP_PKEY_CTRL_RSA_OAEP_LABEL, len, label);
	}

	auto EVP_PKEY_CTX_get_rsa_oaep_md () (EVP_PKEY_CTX* ctx, EVP_MD** pmd)
	{
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
			EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, pmd);
	}

	auto EVP_PKEY_CTX_get0_rsa_oaep_label () (EVP_PKEY_CTX* ctx, ubyte** label)
	{
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
			EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, label);
	}
}


enum EVP_PKEY_CTRL_RSA_PADDING = (EVP_PKEY_ALG_CTRL + 1);
enum EVP_PKEY_CTRL_RSA_PSS_SALTLEN = (EVP_PKEY_ALG_CTRL + 2);

enum EVP_PKEY_CTRL_RSA_KEYGEN_BITS = (EVP_PKEY_ALG_CTRL + 3);
enum EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = (EVP_PKEY_ALG_CTRL + 4);
enum EVP_PKEY_CTRL_RSA_MGF1_MD = (EVP_PKEY_ALG_CTRL + 5);

enum EVP_PKEY_CTRL_GET_RSA_PADDING = (EVP_PKEY_ALG_CTRL + 6);
enum EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = (EVP_PKEY_ALG_CTRL + 7);
enum EVP_PKEY_CTRL_GET_RSA_MGF1_MD = (EVP_PKEY_ALG_CTRL + 8);

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
	enum EVP_PKEY_CTRL_RSA_OAEP_MD    = (EVP_PKEY_ALG_CTRL + 9);
	enum EVP_PKEY_CTRL_RSA_OAEP_LABEL = (EVP_PKEY_ALG_CTRL + 10);
	enum EVP_PKEY_CTRL_GET_RSA_OAEP_MD = (EVP_PKEY_ALG_CTRL + 11);
	enum EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = (EVP_PKEY_ALG_CTRL + 12);
}

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
	enum EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES = (EVP_PKEY_ALG_CTRL + 13);

enum RSA_PKCS1_PADDING = 1;
enum RSA_SSLV23_PADDING = 2;
enum RSA_NO_PADDING = 3;
enum RSA_PKCS1_OAEP_PADDING = 4;
enum RSA_X931_PADDING = 5;
/* EVP_PKEY_ only */
enum RSA_PKCS1_PSS_PADDING = 6;

enum RSA_PKCS1_PADDING_SIZE = 11;

int RSA_set_app_data()(RSA* s, void* arg) { return RSA_set_ex_data(s,0,arg); }
void* RSA_get_app_data()(const(RSA)* s) { return RSA_get_ex_data(s,0); }

RSA* 	RSA_new();
RSA* 	RSA_new_method(ENGINE* engine);
int	RSA_size(const(RSA)* rsa);

/* Deprecated version */
version(OPENSSL_NO_DEPRECATED) {} else {
RSA* 	RSA_generate_key(int bits, c_ulong e,ExternC!(void
	 function(int,int,void*)) callback,void* cb_arg);
} /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
int	RSA_generate_key_ex(RSA* rsa, int bits, BIGNUM* e, BN_GENCB* cb);

int	RSA_check_key(const(RSA)*);
	/* next 4 return -1 on error */
int	RSA_public_encrypt(int flen, const(ubyte)* from,
		ubyte* to, RSA* rsa,int padding);
int	RSA_private_encrypt(int flen, const(ubyte)* from,
		ubyte* to, RSA* rsa,int padding);
int	RSA_public_decrypt(int flen, const(ubyte)* from,
		ubyte* to, RSA* rsa,int padding);
int	RSA_private_decrypt(int flen, const(ubyte)* from,
		ubyte* to, RSA* rsa,int padding);
void	RSA_free (RSA* r);
/* "up" the RSA object's reference count */
int	RSA_up_ref(RSA* r);

int	RSA_flags(const(RSA)* r);

void RSA_set_default_method(const(RSA_METHOD)* meth);
const(RSA_METHOD)* RSA_get_default_method();
const(RSA_METHOD)* RSA_get_method(const(RSA)* rsa);
int RSA_set_method(RSA* rsa, const(RSA_METHOD)* meth);

/* This function needs the memory locking malloc callbacks to be installed */
int RSA_memory_lock(RSA* r);

/* these are the actual SSLeay RSA functions */
const(RSA_METHOD)* RSA_PKCS1_SSLeay();

const(RSA_METHOD)* RSA_null_method();

mixin(DECLARE_ASN1_ENCODE_FUNCTIONS_const!("RSA", "RSAPublicKey"));
mixin(DECLARE_ASN1_ENCODE_FUNCTIONS_const!("RSA", "RSAPrivateKey"));

struct rsa_pss_params_st
	{
	X509_ALGOR *hashAlgorithm;
	X509_ALGOR *maskGenAlgorithm;
	ASN1_INTEGER *saltLength;
	ASN1_INTEGER *trailerField;
	}
alias rsa_pss_params_st RSA_PSS_PARAMS;

mixin(DECLARE_ASN1_FUNCTIONS!"RSA_PSS_PARAMS");

version(OPENSSL_NO_FP_API) {} else {
int	RSA_print_fp(FILE* fp, const(RSA)* r,int offset);
}

version(OPENSSL_NO_BIO) {} else {
int	RSA_print(BIO* bp, const(RSA)* r,int offset);
}

version(OPENSSL_NO_RC4) {} else {
int i2d_RSA_NET(const(RSA)* a, ubyte** pp,
		ExternC!(int function(char* buf, int len, const(char)* prompt, int verify)) cb,
		int sgckey);
RSA* d2i_RSA_NET(RSA** a, const(ubyte)** pp, c_long length,
		 ExternC!(int function(char* buf, int len, const(char)* prompt, int verify)) cb,
		 int sgckey);

int i2d_Netscape_RSA(const(RSA)* a, ubyte** pp,
		     ExternC!(int function(char* buf, int len, const(char)* prompt,
			       int verify)) cb);
RSA* d2i_Netscape_RSA(RSA** a, const(ubyte)** pp, c_long length,
		      ExternC!(int function(char* buf, int len, const(char)* prompt,
				int verify)) cb);
}

/* The following 2 functions sign and verify a X509_SIG ASN1 object
 * inside PKCS#1 padded RSA encryption */
int RSA_sign(int type, const(ubyte)* m, uint m_length,
	ubyte* sigret, uint* siglen, RSA* rsa);
int RSA_verify(int type, const(ubyte)* m, uint m_length,
	const(ubyte)* sigbuf, uint siglen, RSA* rsa);

/* The following 2 function sign and verify a ASN1_OCTET_STRING
 * object inside PKCS#1 padded RSA encryption */
int RSA_sign_ASN1_OCTET_STRING(int type,
	const(ubyte)* m, uint m_length,
	ubyte* sigret, uint* siglen, RSA* rsa);
int RSA_verify_ASN1_OCTET_STRING(int type,
	const(ubyte)* m, uint m_length,
	ubyte* sigbuf, uint siglen, RSA* rsa);

int RSA_blinding_on(RSA* rsa, BN_CTX* ctx);
void RSA_blinding_off(RSA* rsa);
BN_BLINDING* RSA_setup_blinding(RSA* rsa, BN_CTX* ctx);

int RSA_padding_add_PKCS1_type_1(ubyte* to,int tlen,
	const(ubyte)* f,int fl);
int RSA_padding_check_PKCS1_type_1(ubyte* to,int tlen,
	const(ubyte)* f,int fl,int rsa_len);
int RSA_padding_add_PKCS1_type_2(ubyte* to,int tlen,
	const(ubyte)* f,int fl);
int RSA_padding_check_PKCS1_type_2(ubyte* to,int tlen,
	const(ubyte)* f,int fl,int rsa_len);
int PKCS1_MGF1(ubyte* mask, c_long len,
	const(ubyte)* seed, c_long seedlen, const(EVP_MD)* dgst);
int RSA_padding_add_PKCS1_OAEP(ubyte* to,int tlen,
	const(ubyte)* f,int fl,
	const(ubyte)* p,int pl);
int RSA_padding_check_PKCS1_OAEP(ubyte* to,int tlen,
	const(ubyte)* f,int fl,int rsa_len,
	const(ubyte)* p,int pl);
static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
    int RSA_padding_add_PKCS1_OAEP_mgf1(ubyte* to, int tlen,
        const(ubyte)* from, int flen,
        const(ubyte)* param, int plen,
        const(EVP_MD)* md, const(EVP_MD)* mgf1md);
    int RSA_padding_check_PKCS1_OAEP_mgf1(ubyte* to, int tlen,
        const(ubyte)* from, int flen, int num,
        const(ubyte)* param, int plen,
        const(EVP_MD)* md, const(EVP_MD)* mgf1md);
}
int RSA_padding_add_SSLv23(ubyte* to,int tlen,
	const(ubyte)* f,int fl);
int RSA_padding_check_SSLv23(ubyte* to,int tlen,
	const(ubyte)* f,int fl,int rsa_len);
int RSA_padding_add_none(ubyte* to,int tlen,
	const(ubyte)* f,int fl);
int RSA_padding_check_none(ubyte* to,int tlen,
	const(ubyte)* f,int fl,int rsa_len);
int RSA_padding_add_X931(ubyte* to,int tlen,
	const(ubyte)* f,int fl);
int RSA_padding_check_X931(ubyte* to,int tlen,
	const(ubyte)* f,int fl,int rsa_len);
int RSA_X931_hash_id(int nid);

int RSA_verify_PKCS1_PSS(RSA* rsa, const(ubyte)* mHash,
			const(EVP_MD)* Hash, const(ubyte)* EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA* rsa, ubyte* EM,
			const(ubyte)* mHash,
			const(EVP_MD)* Hash, int sLen);

int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const(ubyte)* mHash,
			const(EVP_MD)* Hash, const(EVP_MD)* mgf1Hash,
			const(ubyte)* EM, int sLen);

int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, ubyte* EM,
			const(ubyte)* mHash,
			const(EVP_MD)* Hash, const(EVP_MD)* mgf1Hash, int sLen);

static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
	int RSA_get_ex_new_index(c_long argl, void* argp, CRYPTO_EX_new* new_func,
		CRYPTO_EX_dup* dup_func, CRYPTO_EX_free* free_func);
}
else
{
	auto RSA_get_ex_new_index () (c_long l, void* p, CRYPTO_EX_new* newf,
		CRYPTO_EX_dup* dupf, CRYPTO_EX_free* freef)
	{
		return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef);
	}
}
int RSA_set_ex_data(RSA* r,int idx,void* arg);
void* RSA_get_ex_data(const(RSA)* r, int idx);

RSA* RSAPublicKey_dup(RSA* rsa);
RSA* RSAPrivateKey_dup(RSA* rsa);

/* If this flag is set the RSA method is FIPS compliant and can be used
 * in FIPS mode. This is set in the validated module method. If an
 * application sets this flag in its own methods it is its responsibility
 * to ensure the result is compliant.
 */

enum RSA_FLAG_FIPS_METHOD = 0x0400;

/* If this flag is set the operations normally disabled in FIPS mode are
 * permitted it is then the applications responsibility to ensure that the
 * usage is compliant.
 */

enum RSA_FLAG_NON_FIPS_ALLOW = 0x0400;
/* Application has decided PRNG is good enough to generate a key: don't
 * check.
 */
enum RSA_FLAG_CHECKED = 0x0800;

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_RSA_strings();

/* Error codes for the RSA functions. */

/* Function codes. */
enum RSA_F_CHECK_PADDING_MD = 140;
enum RSA_F_DO_RSA_PRINT = 146;
enum RSA_F_INT_RSA_VERIFY = 145;
enum RSA_F_MEMORY_LOCK = 100;
enum RSA_F_OLD_RSA_PRIV_DECODE = 147;
enum RSA_F_PKEY_RSA_CTRL = 143;
enum RSA_F_PKEY_RSA_CTRL_STR = 144;
enum RSA_F_PKEY_RSA_SIGN = 142;
enum RSA_F_PKEY_RSA_VERIFY = 154;
enum RSA_F_PKEY_RSA_VERIFYRECOVER = 141;
enum RSA_F_RSA_BUILTIN_KEYGEN = 129;
enum RSA_F_RSA_CHECK_KEY = 123;
enum RSA_F_RSA_EAY_PRIVATE_DECRYPT = 101;
enum RSA_F_RSA_EAY_PRIVATE_ENCRYPT = 102;
enum RSA_F_RSA_EAY_PUBLIC_DECRYPT = 103;
enum RSA_F_RSA_EAY_PUBLIC_ENCRYPT = 104;
enum RSA_F_RSA_GENERATE_KEY = 105;
enum RSA_F_RSA_GENERATE_KEY_EX = 155;
enum RSA_F_RSA_ITEM_VERIFY = 156;
enum RSA_F_RSA_MEMORY_LOCK = 130;
enum RSA_F_RSA_NEW_METHOD = 106;
enum RSA_F_RSA_NULL = 124;
enum RSA_F_RSA_NULL_MOD_EXP = 131;
enum RSA_F_RSA_NULL_PRIVATE_DECRYPT = 132;
enum RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 133;
enum RSA_F_RSA_NULL_PUBLIC_DECRYPT = 134;
enum RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 135;
enum RSA_F_RSA_PADDING_ADD_NONE = 107;
enum RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 121;
enum RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 = 154;
enum RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 125;
enum RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 = 148;
enum RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 108;
enum RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 109;
enum RSA_F_RSA_PADDING_ADD_SSLV23 = 110;
enum RSA_F_RSA_PADDING_ADD_X931 = 127;
enum RSA_F_RSA_PADDING_CHECK_NONE = 111;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 122;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 = 153;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 112;
enum RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 113;
enum RSA_F_RSA_PADDING_CHECK_SSLV23 = 114;
enum RSA_F_RSA_PADDING_CHECK_X931 = 128;
enum RSA_F_RSA_PRINT = 115;
enum RSA_F_RSA_PRINT_FP = 116;
enum RSA_F_RSA_PRIVATE_DECRYPT = 150;
enum RSA_F_RSA_PRIVATE_ENCRYPT = 151;
enum RSA_F_RSA_PRIV_DECODE = 137;
enum RSA_F_RSA_PRIV_ENCODE = 138;
enum RSA_F_RSA_PUBLIC_DECRYPT = 152;
enum RSA_F_RSA_PUBLIC_ENCRYPT = 153;
enum RSA_F_RSA_PUB_DECODE = 139;
enum RSA_F_RSA_SETUP_BLINDING = 136;
enum RSA_F_RSA_SIGN = 117;
enum RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 118;
enum RSA_F_RSA_VERIFY = 119;
enum RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 120;
enum RSA_F_RSA_VERIFY_PKCS1_PSS = 126;
enum RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 = 149
;
/* Reason codes. */
enum RSA_R_ALGORITHM_MISMATCH = 100;
enum RSA_R_BAD_E_VALUE = 101;
enum RSA_R_BAD_FIXED_HEADER_DECRYPT = 102;
enum RSA_R_BAD_PAD_BYTE_COUNT = 103;
enum RSA_R_BAD_SIGNATURE = 104;
enum RSA_R_BLOCK_TYPE_IS_NOT_01 = 106;
enum RSA_R_BLOCK_TYPE_IS_NOT_02 = 107;
enum RSA_R_DATA_GREATER_THAN_MOD_LEN = 108;
enum RSA_R_DATA_TOO_LARGE = 109;
enum RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE = 110;
enum RSA_R_DATA_TOO_LARGE_FOR_MODULUS = 132;
enum RSA_R_DATA_TOO_SMALL = 111;
enum RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE = 122;
enum RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY = 112;
enum RSA_R_DMP1_NOT_CONGRUENT_TO_D = 124;
enum RSA_R_DMQ1_NOT_CONGRUENT_TO_D = 125;
enum RSA_R_D_E_NOT_CONGRUENT_TO_1 = 123;
enum RSA_R_FIRST_OCTET_INVALID = 133;
enum RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE = 144;
enum RSA_R_INVALID_DIGEST = 157;
enum RSA_R_INVALID_DIGEST_LENGTH = 143;
enum RSA_R_INVALID_HEADER = 137;
enum RSA_R_INVALID_KEYBITS = 145;
enum RSA_R_INVALID_MESSAGE_LENGTH = 131;
enum RSA_R_INVALID_MGF1_MD = 156;
enum RSA_R_INVALID_PADDING = 138;
enum RSA_R_INVALID_PADDING_MODE = 141;
enum RSA_R_INVALID_PSS_PARAMETERS = 149;
enum RSA_R_INVALID_PSS_SALTLEN = 146;
enum RSA_R_INVALID_SALT_LENGTH = 150;
enum RSA_R_INVALID_TRAILER = 139;
enum RSA_R_INVALID_X931_DIGEST = 142;
enum RSA_R_IQMP_NOT_INVERSE_OF_Q = 126;
enum RSA_R_KEY_SIZE_TOO_SMALL = 120;
enum RSA_R_LAST_OCTET_INVALID = 134;
enum RSA_R_MODULUS_TOO_LARGE = 105;
enum RSA_R_NON_FIPS_RSA_METHOD = 157;
enum RSA_R_NO_PUBLIC_EXPONENT = 140;
enum RSA_R_NULL_BEFORE_BLOCK_MISSING = 113;
enum RSA_R_N_DOES_NOT_EQUAL_P_Q = 127;
enum RSA_R_OAEP_DECODING_ERROR = 121;
enum RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE = 158;
enum RSA_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 148;
enum RSA_R_PADDING_CHECK_FAILED = 114;
enum RSA_R_P_NOT_PRIME = 128;
enum RSA_R_Q_NOT_PRIME = 129;
enum RSA_R_RSA_OPERATIONS_NOT_SUPPORTED = 130;
enum RSA_R_SLEN_CHECK_FAILED = 136;
enum RSA_R_SLEN_RECOVERY_FAILED = 135;
enum RSA_R_SSLV3_ROLLBACK_ATTACK = 115;
enum RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD = 116;
enum RSA_R_UNKNOWN_ALGORITHM_TYPE = 117;
enum RSA_R_UNKNOWN_MASK_DIGEST = 151;
enum RSA_R_UNKNOWN_PADDING_TYPE = 118;
enum RSA_R_UNKNOWN_PSS_DIGEST = 152;
enum RSA_R_UNSUPPORTED_MASK_ALGORITHM = 153;
enum RSA_R_UNSUPPORTED_MASK_PARAMETER = 154;
enum RSA_R_UNSUPPORTED_SIGNATURE_TYPE = 155;
enum RSA_R_VALUE_MISSING = 147;
enum RSA_R_WRONG_SIGNATURE_LENGTH = 119;
