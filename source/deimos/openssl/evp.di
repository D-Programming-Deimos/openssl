/**
 * Bindings for `<openssl/evp.h>`
 *
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
module deimos.openssl.evp;

import deimos.openssl._d_util;

import deimos.openssl.x509; // Needed for X509_ATTRIBUTE.

//#ifdef OPENSSL_ALGORITHM_DEFINES
public import deimos.openssl.opensslconf;
//#else
//# define OPENSSL_ALGORITHM_DEFINES
//public import deimos.openssl.opensslconf;
//# undef OPENSSL_ALGORITHM_DEFINES
//#endif

public import deimos.openssl.types;

public import deimos.openssl.symhacks;

version(OPENSSL_NO_BIO) {} else {
public import deimos.openssl.bio;
}

/*
enum EVP_RC2_KEY_SIZE = 16;
enum EVP_RC4_KEY_SIZE = 16;
enum EVP_BLOWFISH_KEY_SIZE = 16;
enum EVP_CAST5_KEY_SIZE = 16;
enum EVP_RC5_32_12_16_KEY_SIZE = 16;
*/
enum EVP_MAX_MD_SIZE = 64;	/* longest known is SHA512 */
enum EVP_MAX_KEY_LENGTH = 64;
enum EVP_MAX_IV_LENGTH = 16;
enum EVP_MAX_BLOCK_LENGTH = 32;

enum PKCS5_SALT_LEN = 8;
/* Default PKCS#5 iteration count */
enum PKCS5_DEFAULT_ITER = 2048;

public import deimos.openssl.objects;

enum EVP_PK_RSA = 0x0001;
enum EVP_PK_DSA = 0x0002;
enum EVP_PK_DH = 0x0004;
enum EVP_PK_EC = 0x0008;
enum EVP_PKT_SIGN = 0x0010;
enum EVP_PKT_ENC = 0x0020;
enum EVP_PKT_EXCH = 0x0040;
enum EVP_PKS_RSA = 0x0100;
enum EVP_PKS_DSA = 0x0200;
enum EVP_PKS_EC = 0x0400;
enum EVP_PKT_EXP = 0x1000; /* <= 512 bit key */

alias EVP_PKEY_NONE = NID_undef;
alias EVP_PKEY_RSA  = NID_rsaEncryption;
alias EVP_PKEY_RSA2 = NID_rsa;
alias EVP_PKEY_DSA  = NID_dsa;
alias EVP_PKEY_DSA1 = NID_dsa_2;
alias EVP_PKEY_DSA2 = NID_dsaWithSHA;
alias EVP_PKEY_DSA3 = NID_dsaWithSHA1;
alias EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;
alias EVP_PKEY_DH   = NID_dhKeyAgreement;
alias EVP_PKEY_EC   = NID_X9_62_id_ecPublicKey;
alias EVP_PKEY_HMAC = NID_hmac;
alias EVP_PKEY_CMAC = NID_cmac;
alias EVP_PKEY_TLS1_PRF = NID_tls1_prf;
alias EVP_PKEY_HKDF     = NID_hkdf;

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
{
    alias EVP_PKEY_SCRYPT   = NID_id_scrypt;
    alias EVP_PKEY_POLY1305 = NID_poly1305;
    alias EVP_PKEY_SIPHASH  = NID_siphash;
    alias EVP_PKEY_X25519   = NID_X25519;
    alias EVP_PKEY_ED25519  = NID_ED25519;
    alias EVP_PKEY_X448     = NID_X448;
    alias EVP_PKEY_ED448    = NID_ED448;
}

extern (C):
nothrow:

enum EVP_PKEY_MO_SIGN = 0x0001;
enum EVP_PKEY_MO_VERIFY = 0x0002;
enum EVP_PKEY_MO_ENCRYPT = 0x0004;
enum EVP_PKEY_MO_DECRYPT = 0x0008;

EVP_MD* EVP_MD_meth_new(int md_type, int pkey_type);
EVP_MD* EVP_MD_meth_dup(const(EVP_MD)* md);
void EVP_MD_meth_free(EVP_MD* md);

int EVP_MD_meth_set_input_blocksize(EVP_MD* md, int blocksize);
int EVP_MD_meth_set_result_size(EVP_MD* md, int resultsize);
int EVP_MD_meth_set_app_datasize(EVP_MD* md, int datasize);
int EVP_MD_meth_set_flags(EVP_MD* md, c_ulong flags);

int EVP_MD_meth_get_input_blocksize(const(EVP_MD)* md);
int EVP_MD_meth_get_result_size(const(EVP_MD)* md);
int EVP_MD_meth_get_app_datasize(const(EVP_MD)* md);
c_ulong EVP_MD_meth_get_flags(const(EVP_MD)* md);

// Internal types to help define the bindings
private alias EVP_MD_lifetime_fn = int function(EVP_MD_CTX* ctx);
private alias EVP_MD_update_fn   = int function(EVP_MD_CTX* ctx,
	const(void)* data, size_t count);
private alias EVP_MD_final_fn    = int function(EVP_MD_CTX* ctx, ubyte* md);
private alias EVP_MD_copy_fn     = int function(EVP_MD_CTX* ctx, const(EVP_MD_CTX)* from);
private alias EVP_MD_cleanup_fn  = int function(EVP_MD_CTX* ctx,
	const(void)* data, size_t count);
private alias EVP_MD_ctrl_fn     = int function(EVP_MD_CTX* ctx,
	int cmd, int p1, void* p2);

int EVP_MD_meth_set_init(EVP_MD* md, EVP_MD_lifetime_fn init);
int EVP_MD_meth_set_update(EVP_MD* md, EVP_MD_update_fn update);
int EVP_MD_meth_set_final(EVP_MD* md, EVP_MD_final_fn final_);
int EVP_MD_meth_set_copy(EVP_MD* md, EVP_MD_copy_fn copy);
int EVP_MD_meth_set_cleanup(EVP_MD* md, EVP_MD_lifetime_fn cleanup);
int EVP_MD_meth_set_ctrl(EVP_MD* md, EVP_MD_ctrl_fn ctrl);

EVP_MD_lifetime_fn EVP_MD_meth_get_init(const(EVP_MD)* md);
EVP_MD_update_fn EVP_MD_meth_get_update(const(EVP_MD)* md);
EVP_MD_final_fn EVP_MD_meth_get_final(const(EVP_MD)* md);
EVP_MD_copy_fn EVP_MD_meth_get_copy(const(EVP_MD)* md);
EVP_MD_lifetime_fn EVP_MD_meth_get_cleanup(const(EVP_MD)* md);
EVP_MD_ctrl_fn EVP_MD_meth_get_ctrl(const(EVP_MD)* md);

alias evp_sign_method = typeof(*(ExternC!(int function(int type,const(ubyte)* m,
			    uint m_length,ubyte* sigret,
			    uint* siglen, void* key))).init);
alias evp_verify_method = typeof(*(ExternC!(int function(int type,const(ubyte)* m,
			    uint m_length,const(ubyte)* sigbuf,
			    uint siglen, void* key))).init);

enum EVP_MD_FLAG_ONESHOT = 0x0001; /* digest can only handle a single
					* block */

enum EVP_MD_FLAG_PKEY_DIGEST = 0x0002; /* digest is a "clone" digest used
					* which is a copy of an existing
					* one for a specific public key type.
					* EVP_dss1() etc */

/* Digest uses EVP_PKEY_METHOD for signing instead of MD specific signing */

enum EVP_MD_FLAG_PKEY_METHOD_SIGNATURE = 0x0004;

/* DigestAlgorithmIdentifier flags... */

enum EVP_MD_FLAG_DIGALGID_MASK = 0x0018;

/* NULL or absent parameter accepted. Use NULL */

enum EVP_MD_FLAG_DIGALGID_NULL = 0x0000;

/* NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent */

enum EVP_MD_FLAG_DIGALGID_ABSENT = 0x0008;

/* Custom handling via ctrl */

enum EVP_MD_FLAG_DIGALGID_CUSTOM = 0x0018;

enum EVP_MD_FLAG_FIPS = 0x0400; /* Note if suitable for use in FIPS mode */

/* Digest ctrls */

enum EVP_MD_CTRL_DIGALGID = 0x1;
enum EVP_MD_CTRL_MICALG = 0x2;

/* Minimum Algorithm specific ctrl value */

enum EVP_MD_CTRL_ALG_CTRL = 0x1000;

enum EVP_PKEY_NULL_method = "null,null,{0,0,0,0}";

version (OPENSSL_NO_DSA) {
	alias EVP_PKEY_DSA_method = EVP_PKEY_NULL_method;
} else {
	enum EVP_PKEY_DSA_method = "cast(evp_sign_method*)&DSA_sign," ~
		"cast(evp_verify_method*)&DSA_verify,{EVP_PKEY_DSA,EVP_PKEY_DSA2," ~
		"EVP_PKEY_DSA3, EVP_PKEY_DSA4,0}";
}

version(OPENSSL_NO_ECDSA) {
	alias EVP_PKEY_ECDSA_method = EVP_PKEY_NULL_method;
} else {
	enum EVP_PKEY_ECDSA_method = "cast(evp_sign_method*)&ECDSA_sign," ~
		"cast(evp_verify_method*)&ECDSA_verify,{EVP_PKEY_EC,0,0,0}";
}

version (OPENSSL_NO_RSA) {
	alias EVP_PKEY_RSA_method = EVP_PKEY_NULL_method;
	alias EVP_PKEY_RSA_ASN1_OCTET_STRING_method = EVP_PKEY_NULL_method;
} else {
	enum EVP_PKEY_RSA_method = "cast(evp_sign_method*)&RSA_sign," ~
		"cast(evp_verify_method*)RSA_verify,{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}";
 	enum EVP_PKEY_RSA_ASN1_OCTET_STRING_method =
		"cast(evp_sign_method*)&RSA_sign_ASN1_OCTET_STRING," ~
		"cast(evp_verify_method*)RSA_verify_ASN1_OCTET_STRING," ~
		"{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}";
}

// #endif /* !EVP_MD */

/* values for EVP_MD_CTX flags */

enum EVP_MD_CTX_FLAG_ONESHOT = 0x0001; /* digest update will be called
						* once only */
enum EVP_MD_CTX_FLAG_CLEANED = 0x0002; /* context has already been
						* cleaned */
enum EVP_MD_CTX_FLAG_REUSE = 0x0004; /* Don't free up ctx->md_data
						* in EVP_MD_CTX_reset */
/* FIPS and pad options are ignored in 1.0.0, definitions are here
 * so we don't accidentally reuse the values for other purposes.
 */

enum EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = 0x0008;	/* Allow use of non FIPS digest
						 * in FIPS mode */

/* The following PAD options are also currently ignored in 1.0.0, digest
 * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
 * instead.
 */
enum EVP_MD_CTX_FLAG_PAD_MASK = 0xF0;	/* RSA mode to use */
enum EVP_MD_CTX_FLAG_PAD_PKCS1 = 0x00;	/* PKCS#1 v1.5 mode */
enum EVP_MD_CTX_FLAG_PAD_X931 = 0x10;	/* X9.31 mode */
enum EVP_MD_CTX_FLAG_PAD_PSS = 0x20;	/* PSS mode */

enum EVP_MD_CTX_FLAG_NO_INIT = 0x0100; /* Don't initialize md_data */

EVP_CIPHER* EVP_CIPHER_meth_new(int cipher_type, int block_size, int key_len);
EVP_CIPHER* EVP_CIPHER_meth_dup(const(EVP_CIPHER)* cipher);
void EVP_CIPHER_meth_free(EVP_CIPHER* cipher);

int EVP_CIPHER_meth_set_iv_length(EVP_CIPHER* cipher, int iv_len);
int EVP_CIPHER_meth_set_flags(EVP_CIPHER* cipher, c_ulong flags);
int EVP_CIPHER_meth_set_impl_ctx_size(EVP_CIPHER* cipher, int ctx_size);

private alias EVP_CIPHER_init_fn = int function(EVP_CIPHER_CTX* ctx,
	const(ubyte)* key, const(ubyte)* iv, int enc);
private alias EVP_CIPHER_do_fn = int function(EVP_CIPHER_CTX* ctx,
	ubyte* out_, const(ubyte)* in_, size_t inl);
private alias EVP_CIPHER_cleanup_fn = int function(EVP_CIPHER_CTX* ctx);
private alias EVP_CIPHER_asn1_parameters_fn = int function(EVP_CIPHER_CTX* ctx, ASN1_TYPE* params);
private alias EVP_CIPHER_ctrl_fn = int function(EVP_CIPHER_CTX* ctx,
	int type, int arg, void* ptr);

int EVP_CIPHER_meth_set_init(EVP_CIPHER* cipher, EVP_CIPHER_init_fn init);
int EVP_CIPHER_meth_set_do_cipher(EVP_CIPHER* cipher, EVP_CIPHER_do_fn do_cipher);
int EVP_CIPHER_meth_set_cleanup(EVP_CIPHER* cipher, EVP_CIPHER_cleanup_fn cleanup);
int EVP_CIPHER_meth_set_set_asn1_params(EVP_CIPHER* cipher, EVP_CIPHER_asn1_parameters_fn set);
int EVP_CIPHER_meth_set_get_asn1_params(EVP_CIPHER* cipher, EVP_CIPHER_asn1_parameters_fn get);
int EVP_CIPHER_meth_set_ctrl(EVP_CIPHER* cipher, EVP_CIPHER_ctrl_fn ctrl);

EVP_CIPHER_init_fn EVP_CIPHER_meth_get_init(const(EVP_CIPHER)* cipher);
EVP_CIPHER_do_fn EVP_CIPHER_meth_get_do_cipher(const(EVP_CIPHER)* cipher);
EVP_CIPHER_cleanup_fn EVP_CIPHER_meth_get_cleanup(const(EVP_CIPHER)* cipher);
EVP_CIPHER_asn1_parameters_fn EVP_CIPHER_meth_get_set_asn1_params(const(EVP_CIPHER)* cipher);
EVP_CIPHER_asn1_parameters_fn EVP_CIPHER_meth_get_get_asn1_params(const(EVP_CIPHER)* cipher);
EVP_CIPHER_ctrl_fn EVP_CIPHER_meth_get_ctrl(const(EVP_CIPHER)* cipher);

/* Values for cipher flags */

/* Modes for ciphers */

enum EVP_CIPH_STREAM_CIPHER = 0x0;
enum EVP_CIPH_ECB_MODE = 0x1;
enum EVP_CIPH_CBC_MODE = 0x2;
enum EVP_CIPH_CFB_MODE = 0x3;
enum EVP_CIPH_OFB_MODE = 0x4;
enum EVP_CIPH_CTR_MODE = 0x5;
enum EVP_CIPH_GCM_MODE = 0x6;
enum EVP_CIPH_CCM_MODE = 0x7;
enum EVP_CIPH_XTS_MODE  = 0x10001;
enum EVP_CIPH_WRAP_MODE = 0x10002;
enum EVP_CIPH_OCB_MODE  = 0x10003;
enum EVP_CIPH_MODE      = 0xF0007;
/* Set if variable length cipher */
enum EVP_CIPH_VARIABLE_LENGTH = 0x8;
/* Set if the iv handling should be done by the cipher itself */
enum EVP_CIPH_CUSTOM_IV = 0x10;
/* Set if the cipher's init() function should be called if key is NULL */
enum EVP_CIPH_ALWAYS_CALL_INIT = 0x20;
/* Call ctrl() to init cipher parameters */
enum EVP_CIPH_CTRL_INIT = 0x40;
/* Don't use standard key length function */
enum EVP_CIPH_CUSTOM_KEY_LENGTH = 0x80;
/* Don't use standard block padding */
enum EVP_CIPH_NO_PADDING = 0x100;
/* cipher handles random key generation */
enum EVP_CIPH_RAND_KEY = 0x200;
/* cipher has its own additional copying logic */
enum EVP_CIPH_CUSTOM_COPY = 0x400;
/* Allow use default ASN1 get/set iv */
enum EVP_CIPH_FLAG_DEFAULT_ASN1 = 0x1000;
/* Buffer length in bits not bytes: CFB1 mode only */
enum EVP_CIPH_FLAG_LENGTH_BITS = 0x2000;
/* Note if suitable for use in FIPS mode */
enum EVP_CIPH_FLAG_FIPS = 0x4000;
/* Allow non FIPS cipher in FIPS mode */
enum EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0x8000;
/* Cipher handles any and all padding logic as well
 * as finalisation.
 */
enum EVP_CIPH_FLAG_CUSTOM_CIPHER = 0x100000;
enum EVP_CIPH_FLAG_AEAD_CIPHER = 0x200000;

/* ctrl() values */

enum EVP_CTRL_INIT = 0x0;
enum EVP_CTRL_SET_KEY_LENGTH = 0x1;
enum EVP_CTRL_GET_RC2_KEY_BITS = 0x2;
enum EVP_CTRL_SET_RC2_KEY_BITS = 0x3;
enum EVP_CTRL_GET_RC5_ROUNDS = 0x4;
enum EVP_CTRL_SET_RC5_ROUNDS = 0x5;
enum EVP_CTRL_RAND_KEY = 0x6;
enum EVP_CTRL_PBE_PRF_NID = 0x7;
enum EVP_CTRL_COPY = 0x8;
enum EVP_CTRL_GCM_SET_IVLEN = 0x9;
enum EVP_CTRL_GCM_GET_TAG = 0x10;
enum EVP_CTRL_GCM_SET_TAG = 0x11;
enum EVP_CTRL_GCM_SET_IV_FIXED = 0x12;
enum EVP_CTRL_GCM_IV_GEN = 0x13;
alias EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN;
alias EVP_CTRL_CCM_GET_TAG = EVP_CTRL_GCM_GET_TAG;
alias EVP_CTRL_CCM_SET_TAG = EVP_CTRL_GCM_SET_TAG;
enum EVP_CTRL_CCM_SET_L = 0x14;
enum EVP_CTRL_CCM_SET_MSGLEN = 0x15;
/* AEAD cipher deduces payload length and returns number of bytes
 * required to store MAC and eventual padding. Subsequent call to
 * EVP_Cipher even appends/verifies MAC.
 */
enum EVP_CTRL_AEAD_TLS1_AAD = 0x16;
/* Used by composite AEAD ciphers, no-op in GCM, CCM... */
enum EVP_CTRL_AEAD_SET_MAC_KEY = 0x17;
/* Set the GCM invocation field, decrypt only */
enum EVP_CTRL_GCM_SET_IV_INV = 0x18;
enum EVP_CTRL_TLS1_1_MULTIBLOCK_AAD         = 0x19;
enum EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT     = 0x1a;
enum EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT     = 0x1b;
enum EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = 0x1c;

enum EVP_CTRL_SSL3_MASTER_SECRET            = 0x1d;

/* EVP_CTRL_SET_SBOX takes the char * specifying S-boxes */
enum EVP_CTRL_SET_SBOX                      = 0x1e;
/*
 * EVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
 * pre-allocated buffer with specified size
 */
enum EVP_CTRL_SBOX_USED                     = 0x1f;
/* EVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
 * 0 switches meshing off
 */
enum EVP_CTRL_KEY_MESH                      = 0x20;
/* EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode */
enum EVP_CTRL_BLOCK_PADDING_MODE            = 0x21;

/* Set the output buffers to use for a pipelined operation */
enum EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS      = 0x22;
/* Set the input buffers to use for a pipelined operation */
enum EVP_CTRL_SET_PIPELINE_INPUT_BUFS       = 0x23;
/* Set the input buffer lengths to use for a pipelined operation */
enum EVP_CTRL_SET_PIPELINE_INPUT_LENS       = 0x24;

/* Padding modes */
enum EVP_PADDING_PKCS7      = 1;
enum EVP_PADDING_ISO7816_4  = 2;
enum EVP_PADDING_ANSI923    = 3;
enum EVP_PADDING_ISO10126   = 4;
enum EVP_PADDING_ZERO       = 5;

/* RFC 5246 defines additional data to be 13 bytes in length */
enum EVP_AEAD_TLS1_AAD_LEN  = 13;

/* GCM TLS constants */
/* Length of fixed part of IV derived from PRF */
enum EVP_GCM_TLS_FIXED_IV_LEN = 4;
/* Length of explicit part of IV part of TLS records */
enum EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;
/* Length of tag for TLS */
enum EVP_GCM_TLS_TAG_LEN = 16;

/* Length of fixed part of IV derived from PRF */
enum EVP_CCM_TLS_FIXED_IV_LEN    = 4;
/* Length of explicit part of IV part of TLS records */
enum EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;

struct evp_cipher_info_st {
	const(EVP_CIPHER)* cipher;
	ubyte[EVP_MAX_IV_LENGTH] iv;
	}
alias EVP_CIPHER_INFO = evp_cipher_info_st;

struct evp_cipher_ctx_st
	{
	const(EVP_CIPHER)* cipher;
	ENGINE* engine;	/* functional reference if 'cipher' is ENGINE-provided */
	int encrypt;		/* encrypt or decrypt */
	int buf_len;		/* number we have left */

	ubyte[EVP_MAX_IV_LENGTH]  oiv;	/* original iv */
	ubyte[EVP_MAX_IV_LENGTH]  iv;	/* working iv */
	ubyte[EVP_MAX_BLOCK_LENGTH] buf;/* saved partial block */
	int num;				/* used by cfb/ofb mode */

	void* app_data;		/* application stuff */
	int key_len;		/* May change for variable length cipher */
	c_ulong flags;	/* Various flags */
	void* cipher_data; /* per EVP data */
	int final_used;
	int block_mask;
	ubyte[EVP_MAX_BLOCK_LENGTH] final_;/* possible final block */
	} /* EVP_CIPHER_CTX */;

struct evp_Encode_Ctx_st {
	int num;	/* number saved in a partial encode/decode */
	int length;	/* The length is either the output line length
			 * (in input bytes) or the shortest input line
			 * length that is ok.  Once decoding begins,
			 * the length is adjusted up each time a longer
			 * line is decoded */
	ubyte[80] enc_data;	/* data to encode */
	int line_num;	/* number read on current line */
	int expect_nl;
	}
alias EVP_ENCODE_CTX = evp_Encode_Ctx_st;

/* Password based encryption function */
alias typeof(*(ExternC!(int function(EVP_CIPHER_CTX* ctx, const(char)* pass, int passlen,
		ASN1_TYPE* param, const(EVP_CIPHER)* cipher,
                const(EVP_MD)* md, int en_de))).init) EVP_PBE_KEYGEN;

version(OPENSSL_NO_RSA) {} else {
	auto EVP_PKEY_assign_RSA()(EVP_PKEY* pkey, RSA* key) {
		return EVP_PKEY_assign(pkey,EVP_PKEY_RSA,cast(void*)key);
	}
}

version(OPENSSL_NO_DSA) {} else {
	auto EVP_PKEY_assign_RSA()(EVP_PKEY* pkey, DSA* key) {
		return EVP_PKEY_assign(pkey,EVP_PKEY_DSA,cast(void*)key);
	}
}

version(OPENSSL_NO_DH) {} else {
	auto EVP_PKEY_assign_DH()(EVP_PKEY* pkey, DH* key) {
		return EVP_PKEY_assign(pkey,EVP_PKEY_DH,cast(void*)key);
	}
}

version(OPENSSL_NO_EC) {} else {
	auto EVP_PKEY_assign_EC_KEY()(EVP_PKEY* pkey, EC_KEY* key) {
		return EVP_PKEY_assign(pkey,EVP_PKEY_EC,cast(void*)key);
	}
}

/* Add some extra combinations */
auto EVP_get_digestbynid()(int a) { return EVP_get_digestbyname(OBJ_nid2sn(a)); }
auto EVP_get_digestbyobj()(const(ASN1_OBJECT)* a) { return EVP_get_digestbynid(OBJ_obj2nid(a)); }
auto EVP_get_cipherbynid()(int a) { return EVP_get_cipherbyname(OBJ_nid2sn(a)); }
auto EVP_get_cipherbyobj()(const(ASN1_OBJECT)* a) { return EVP_get_cipherbynid(OBJ_obj2nid(a)); }

int EVP_MD_type(const(EVP_MD)* md);
alias EVP_MD_nid = EVP_MD_type;
auto EVP_MD_name()(const(EVP_MD)* e) { return OBJ_nid2sn(EVP_MD_nid(e)); }
int EVP_MD_pkey_type(const(EVP_MD)* md);
int EVP_MD_size(const(EVP_MD)* md);
int EVP_MD_block_size(const(EVP_MD)* md);
c_ulong EVP_MD_flags(const(EVP_MD)* md);

const(EVP_MD)* EVP_MD_CTX_md(const(EVP_MD_CTX)* ctx);
auto EVP_MD_CTX_size()(const(EVP_MD_CTX)* e) { return EVP_MD_size(EVP_MD_CTX_md(e)); }
auto EVP_MD_CTX_block_size()(const(EVP_MD_CTX)* e) { return EVP_MD_block_size(EVP_MD_CTX_md(e)); }
auto EVP_MD_CTX_type()(const(EVP_MD_CTX)* e) { return EVP_MD_type(EVP_MD_CTX_md(e)); }
EVP_PKEY_CTX* EVP_MD_CTX_pkey_ctx(const(EVP_MD_CTX)* ctx);
void* EVP_MD_CTX_md_data(const(EVP_MD_CTX)* ctx);

int EVP_CIPHER_nid(const(EVP_CIPHER)* cipher);
auto EVP_CIPHER_name()(const(EVP_CIPHER)* e){ return OBJ_nid2sn(EVP_CIPHER_nid(e)); }
int EVP_CIPHER_block_size(const(EVP_CIPHER)* cipher);
int EVP_CIPHER_impl_ctx_size(const(EVP_CIPHER)* cipher);
int EVP_CIPHER_key_length(const(EVP_CIPHER)* cipher);
int EVP_CIPHER_iv_length(const(EVP_CIPHER)* cipher);
c_ulong EVP_CIPHER_flags(const(EVP_CIPHER)* cipher);
auto EVP_CIPHER_mode()(const(EVP_CIPHER)* e) { return (EVP_CIPHER_flags(e) & EVP_CIPH_MODE); }

const(EVP_CIPHER)* EVP_CIPHER_CTX_cipher(const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_encrypting(const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_nid(const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_block_size(const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_key_length(const(EVP_CIPHER_CTX)* ctx);
int EVP_CIPHER_CTX_iv_length(const(EVP_CIPHER_CTX)* ctx);
const(ubyte)* EVP_CIPHER_CTX_iv(const(EVP_CIPHER_CTX)* ctx);
const(ubyte)* EVP_CIPHER_CTX_original_iv(const(EVP_CIPHER_CTX)* ctx);
ubyte* EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX* ctx);
ubyte* EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX* ctx);
int EVP_CIPHER_CTX_num(const(EVP_CIPHER_CTX)* ctx);
void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX* ctx, int num);
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX* out_, const(EVP_CIPHER_CTX)* in_);
void* EVP_CIPHER_CTX_get_app_data(const(EVP_CIPHER_CTX)* ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX* ctx, void* data);
auto EVP_CIPHER_CTX_type()(const(EVP_CIPHER_CTX)* c) { return EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c)); }
static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
	c_ulong EVP_CIPHER_CTX_flags(const(EVP_CIPHER_CTX)* ctx);
	auto EVP_CIPHER_CTX_mode()(const(EVP_CIPHER_CTX)* e) { return (EVP_CIPHER_CTX_flags(e) & EVP_CIPH_MODE); }
}
else
{
	auto EVP_CIPHER_CTX_flags()(const(EVP_CIPHER_CTX)* e) { return EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(c)); }
    auto EVP_CIPHER_CTX_mode()(const(EVP_CIPHER_CTX)* e) { return EVP_CIPHER_mode(EVP_CIPHER_CTX_cipher(c)); }
}

auto EVP_ENCODE_LENGTH(T)(T l) { return (((l+2)/3*4)+(l/48+1)*2+80); }
auto EVP_DECODE_LENGTH(T)(T l) { return ((l+3)/4*3+80); }

alias EVP_SignInit_ex   = EVP_DigestInit_ex;
alias EVP_SignInit      = EVP_DigestInit;
alias EVP_SignUpdate    = EVP_DigestUpdate;
alias EVP_VerifyInit_ex = EVP_DigestInit_ex;
alias EVP_VerifyInit    = EVP_DigestInit;
alias EVP_VerifyUpdate  = EVP_DigestUpdate;
alias EVP_OpenUpdate    = EVP_DecryptUpdate;
alias EVP_SealUpdate    = EVP_EncryptUpdate;
alias EVP_DigestSignUpdate   = EVP_DigestUpdate;
alias EVP_DigestVerifyUpdate = EVP_DigestUpdate;

void BIO_set_md()(BIO* b,const(EVP_MD)* md) { return BIO_ctrl(b,BIO_C_SET_MD,0,md); }
auto BIO_get_md()(BIO* b,EVP_MD** mdp) { return BIO_ctrl(b,BIO_C_GET_MD,0,mdp); }
auto BIO_get_md_ctx()(BIO* b,EVP_MD_CTX** mdcp) { return BIO_ctrl(b,BIO_C_GET_MD_CTX,0,mdcp); }
auto BIO_set_md_ctx()(BIO* b,EVP_MD_CTX** mdcp) { return BIO_ctrl(b,BIO_C_SET_MD_CTX,0,mdcp); }
auto BIO_get_cipher_status()(BIO* b) { return BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,null); }
auto BIO_get_cipher_ctx()(BIO* b,EVP_CIPHER_CTX** c_pp) { return BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,c_pp); }

int EVP_Cipher(EVP_CIPHER_CTX* c,
		ubyte* out_,
		const(ubyte)* in_,
		uint inl);

auto EVP_add_cipher_alias()(const(char)* n,const(char)* alias_) {
	return OBJ_NAME_add(alias_,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n));
}
auto EVP_add_digest_alias()(const(char)* n,const(char)* alias_) {
	return OBJ_NAME_add(alias_,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n));
}
auto EVP_delete_cipher_alias()(const(char)* alias_) {
	return OBJ_NAME_remove(alias_,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
}
auto EVP_delete_digest_alias()(const(char)* alias_) {
	return OBJ_NAME_remove(alias_,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);
}

static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
	EVP_MD_CTX* EVP_MD_CTX_create();
	void EVP_MD_CTX_init(EVP_MD_CTX* ctx);
	void EVP_MD_CTX_destroy(EVP_MD_CTX* ctx);
}
else
{
    // https://github.com/openssl/openssl/commit/959ed5316c84d0e12ad18acfd40cefe15603ddfb
    // https://github.com/openssl/openssl/commit/f8137a62d94c0a5809a4363b7b4aab3adcb8201c
    EVP_MD_CTX* EVP_MD_CTX_new();
    int EVP_MD_CTX_reset(EVP_MD_CTX* ctx);
    void EVP_MD_CTX_free(EVP_MD_CTX* ctx);
	alias EVP_MD_CTX_create  = EVP_MD_CTX_new;
	alias EVP_MD_CTX_init    = EVP_MD_CTX_reset;
	alias EVP_MD_CTX_destroy = EVP_MD_CTX_free;
}

// https://github.com/openssl/openssl/commit/74cabf3fef77ab73c45e27cf6ed90f6db020e7c7
static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
	int	EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx);

int EVP_MD_CTX_ctrl(EVP_MD_CTX* ctx, int cmd, int p1, void* p2);
int     EVP_MD_CTX_copy_ex(EVP_MD_CTX* out_,const(EVP_MD_CTX)* in_);
void	EVP_MD_CTX_set_flags(EVP_MD_CTX* ctx, int flags);
void	EVP_MD_CTX_clear_flags(EVP_MD_CTX* ctx, int flags);
int 	EVP_MD_CTX_test_flags(const(EVP_MD_CTX)* ctx,int flags);
int	EVP_DigestInit_ex(EVP_MD_CTX* ctx, const(EVP_MD)* type, ENGINE* impl);
int	EVP_DigestUpdate(EVP_MD_CTX* ctx,const(void)* d,
			 size_t cnt);
int	EVP_DigestFinal_ex(EVP_MD_CTX* ctx,ubyte* md,uint* s);
int	EVP_Digest(const(void)* data, size_t count,
		ubyte* md, uint* size, const(EVP_MD)* type, ENGINE* impl);

int     EVP_MD_CTX_copy(EVP_MD_CTX* out_,const(EVP_MD_CTX)* in_);
int	EVP_DigestInit(EVP_MD_CTX* ctx, const(EVP_MD)* type);
int	EVP_DigestFinal(EVP_MD_CTX* ctx,ubyte* md,uint* s);

int	EVP_read_pw_string(char* buf,int length,const(char)* prompt,int verify);
int	EVP_read_pw_string_min(char* buf,int minlen,int maxlen,const(char)* prompt,int verify);
void	EVP_set_pw_prompt(const(char)* prompt);
char* 	EVP_get_pw_prompt();

int	EVP_BytesToKey(const(EVP_CIPHER)* type,const(EVP_MD)* md,
		const(ubyte)* salt, const(ubyte)* data,
		int datal, int count, ubyte* key,ubyte* iv);

void	EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX* ctx, int flags);
void	EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX* ctx, int flags);
int 	EVP_CIPHER_CTX_test_flags(const(EVP_CIPHER_CTX)* ctx,int flags);

int	EVP_EncryptInit(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* cipher,
		const(ubyte)* key, const(ubyte)* iv);
int	EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* cipher, ENGINE* impl,
		const(ubyte)* key, const(ubyte)* iv);
int	EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx, ubyte* out_,
		int* outl, const(ubyte)* in_, int inl);
int	EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);
int	EVP_EncryptFinal(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);

int	EVP_DecryptInit(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* cipher,
		const(ubyte)* key, const(ubyte)* iv);
int	EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* cipher, ENGINE* impl,
		const(ubyte)* key, const(ubyte)* iv);
int	EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, ubyte* out_,
		int* outl, const(ubyte)* in_, int inl);
int	EVP_DecryptFinal(EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
int	EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);

int	EVP_CipherInit(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* cipher,
		       const(ubyte)* key,const(ubyte)* iv,
		       int enc);
int	EVP_CipherInit_ex(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* cipher, ENGINE* impl,
		       const(ubyte)* key,const(ubyte)* iv,
		       int enc);
int	EVP_CipherUpdate(EVP_CIPHER_CTX* ctx, ubyte* out_,
		int* outl, const(ubyte)* in_, int inl);
int	EVP_CipherFinal(EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);
int	EVP_CipherFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);

int	EVP_SignFinal(EVP_MD_CTX* ctx,ubyte* md,uint* s,
		EVP_PKEY* pkey);

int	EVP_VerifyFinal(EVP_MD_CTX* ctx,const(ubyte)* sigbuf,
		uint siglen,EVP_PKEY* pkey);

int	EVP_DigestSignInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx,
			const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int	EVP_DigestSignFinal(EVP_MD_CTX* ctx,
			ubyte* sigret, size_t* siglen);

int	EVP_DigestVerifyInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx,
			const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int	EVP_DigestVerifyFinal(EVP_MD_CTX* ctx,
			ubyte* sig, size_t siglen);

int	EVP_OpenInit(EVP_CIPHER_CTX* ctx,const(EVP_CIPHER)* type,
		const(ubyte)* ek, int ekl, const(ubyte)* iv,
		EVP_PKEY* priv);
int	EVP_OpenFinal(EVP_CIPHER_CTX* ctx, ubyte* out_, int* outl);

int	EVP_SealInit(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type,
		 ubyte** ek, int* ekl, ubyte* iv,
		EVP_PKEY** pubk, int npubk);
int	EVP_SealFinal(EVP_CIPHER_CTX* ctx,ubyte* out_,int* outl);

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
	EVP_ENCODE_CTX* EVP_ENCODE_CTX_new();
	void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX* ctx);
	int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX* ctx);
    int EVP_ENCODE_CTX_copy(EVP_ENCODE_CTX* dctx, EVP_ENCODE_CTX* sctx);
    int EVP_ENCODE_CTX_num(EVP_ENCODE_CTX* ctx);
}

void	EVP_EncodeInit(EVP_ENCODE_CTX* ctx);
static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
    alias EVP_EncodeUpdateRT = int;
else
    alias EVP_EncodeUpdateRT = void;
EVP_EncodeUpdateRT	EVP_EncodeUpdate(EVP_ENCODE_CTX* ctx,ubyte* out_,int* outl,
		const(ubyte)* in_,int inl);
void	EVP_EncodeFinal(EVP_ENCODE_CTX* ctx,ubyte* out_,int* outl);
int	EVP_EncodeBlock(ubyte* t, const(ubyte)* f, int n);

void	EVP_DecodeInit(EVP_ENCODE_CTX* ctx);
int	EVP_DecodeUpdate(EVP_ENCODE_CTX* ctx,ubyte* out_,int* outl,
		const(ubyte)* in_, int inl);
int	EVP_DecodeFinal(EVP_ENCODE_CTX* ctx, ubyte* out_, int* outl);
int	EVP_DecodeBlock(ubyte* t, const(ubyte)* f, int n);

static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
	void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX* a);
	int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX* a);
}
else
{
    int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX* c);

    alias EVP_CIPHER_CTX_init = EVP_CIPHER_CTX_reset;
    alias EVP_CIPHER_CTX_cleanup = EVP_CIPHER_CTX_reset;
}
EVP_CIPHER_CTX* EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX* x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX* c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX* ctx, ubyte* key);

version(OPENSSL_NO_BIO) {} else {
BIO_METHOD* BIO_f_md();
BIO_METHOD* BIO_f_base64();
BIO_METHOD* BIO_f_cipher();
BIO_METHOD* BIO_f_reliable();
void BIO_set_cipher(BIO* b,const(EVP_CIPHER)* c,const(ubyte)* k,
		const(ubyte)* i, int enc);
}

const(EVP_MD)* EVP_md_null();
version(OPENSSL_NO_MD2) {} else {
const(EVP_MD)* EVP_md2();
}
version(OPENSSL_NO_MD4) {} else {
const(EVP_MD)* EVP_md4();
}
version(OPENSSL_NO_MD5) {} else {
const(EVP_MD)* EVP_md5();
}
const(EVP_MD)* EVP_blake2b512();
const(EVP_MD)* EVP_blake2s256();
version(OPENSSL_NO_SHA) {} else {
const(EVP_MD)* EVP_sha();
const(EVP_MD)* EVP_sha1();
const(EVP_MD)* EVP_dss();
const(EVP_MD)* EVP_dss1();
const(EVP_MD)* EVP_ecdsa();
}
version(OPENSSL_NO_SHA256) {} else {
const(EVP_MD)* EVP_sha224();
const(EVP_MD)* EVP_sha256();
}
version(OPENSSL_NO_SHA512) {} else {
const(EVP_MD)* EVP_sha384();
const(EVP_MD)* EVP_sha512();
}
version(OPENSSL_NO_MDC2) {} else {
const(EVP_MD)* EVP_mdc2();
}
version(OPENSSL_NO_RIPEMD) {} else {
const(EVP_MD)* EVP_ripemd160();
}
version(OPENSSL_NO_WHIRLPOOL) {} else {
const(EVP_MD)* EVP_whirlpool();
}
const(EVP_CIPHER)* EVP_enc_null();		/* does nothing :-) */
version (OPENSSL_NO_DES) {} else {
const(EVP_CIPHER)* EVP_des_ecb();
const(EVP_CIPHER)* EVP_des_ede();
const(EVP_CIPHER)* EVP_des_ede3();
const(EVP_CIPHER)* EVP_des_ede_ecb();
const(EVP_CIPHER)* EVP_des_ede3_ecb();
const(EVP_CIPHER)* EVP_des_cfb64();
alias EVP_des_cfb = EVP_des_cfb64;
const(EVP_CIPHER)* EVP_des_cfb1();
const(EVP_CIPHER)* EVP_des_cfb8();
const(EVP_CIPHER)* EVP_des_ede_cfb64();
alias EVP_des_ede_cfb = EVP_des_ede_cfb64;
version (none) {
const(EVP_CIPHER)* EVP_des_ede_cfb1();
const(EVP_CIPHER)* EVP_des_ede_cfb8();
}
const(EVP_CIPHER)* EVP_des_ede3_cfb64();
alias EVP_des_ede3_cfb = EVP_des_ede3_cfb64;
const(EVP_CIPHER)* EVP_des_ede3_cfb1();
const(EVP_CIPHER)* EVP_des_ede3_cfb8();
const(EVP_CIPHER)* EVP_des_ofb();
const(EVP_CIPHER)* EVP_des_ede_ofb();
const(EVP_CIPHER)* EVP_des_ede3_ofb();
const(EVP_CIPHER)* EVP_des_cbc();
const(EVP_CIPHER)* EVP_des_ede_cbc();
const(EVP_CIPHER)* EVP_des_ede3_cbc();
const(EVP_CIPHER)* EVP_desx_cbc();
/* This should now be supported through the dev_crypto ENGINE. But also, why are
 * rc4 and md5 declarations made here inside a "NO_DES" precompiler branch? */
//#if 0
//# ifdef OPENSSL_OPENBSD_DEV_CRYPTO
//const(EVP_CIPHER)* EVP_dev_crypto_des_ede3_cbc();
//const(EVP_CIPHER)* EVP_dev_crypto_rc4();
//const(EVP_MD)* EVP_dev_crypto_md5();
//# endif
//#endif
}
version(OPENSSL_NO_RC4) {} else {
const(EVP_CIPHER)* EVP_rc4();
const(EVP_CIPHER)* EVP_rc4_40();
version(OPENSSL_NO_MD5) {} else {
const(EVP_CIPHER)* EVP_rc4_hmac_md5();
}
}
version(OPENSSL_NO_IDEA) {} else {
const(EVP_CIPHER)* EVP_idea_ecb();
const(EVP_CIPHER)* EVP_idea_cfb64();
alias EVP_idea_cfb = EVP_idea_cfb64;
const(EVP_CIPHER)* EVP_idea_ofb();
const(EVP_CIPHER)* EVP_idea_cbc();
}
version(OPENSSL_NO_RC2) {} else {
const(EVP_CIPHER)* EVP_rc2_ecb();
const(EVP_CIPHER)* EVP_rc2_cbc();
const(EVP_CIPHER)* EVP_rc2_40_cbc();
const(EVP_CIPHER)* EVP_rc2_64_cbc();
const(EVP_CIPHER)* EVP_rc2_cfb64();
alias EVP_rc2_cfb = EVP_rc2_cfb64;
const(EVP_CIPHER)* EVP_rc2_ofb();
}
version(OPENSSL_NO_BF) {} else {
const(EVP_CIPHER)* EVP_bf_ecb();
const(EVP_CIPHER)* EVP_bf_cbc();
const(EVP_CIPHER)* EVP_bf_cfb64();
alias EVP_bf_cfb = EVP_bf_cfb64;
const(EVP_CIPHER)* EVP_bf_ofb();
}
version(OPENSSL_NO_CAST) {} else {
const(EVP_CIPHER)* EVP_cast5_ecb();
const(EVP_CIPHER)* EVP_cast5_cbc();
const(EVP_CIPHER)* EVP_cast5_cfb64();
alias EVP_cast5_cfb = EVP_cast5_cfb64;
const(EVP_CIPHER)* EVP_cast5_ofb();
}
version(OPENSSL_NO_RC5) {} else {
const(EVP_CIPHER)* EVP_rc5_32_12_16_cbc();
const(EVP_CIPHER)* EVP_rc5_32_12_16_ecb();
const(EVP_CIPHER)* EVP_rc5_32_12_16_cfb64();
alias EVP_rc5_32_12_16_cfb = EVP_rc5_32_12_16_cfb64;
const(EVP_CIPHER)* EVP_rc5_32_12_16_ofb();
}
version(OPENSSL_NO_AES) {} else {
const(EVP_CIPHER)* EVP_aes_128_ecb();
const(EVP_CIPHER)* EVP_aes_128_cbc();
const(EVP_CIPHER)* EVP_aes_128_cfb1();
const(EVP_CIPHER)* EVP_aes_128_cfb8();
const(EVP_CIPHER)* EVP_aes_128_cfb128();
alias EVP_aes_128_cfb = EVP_aes_128_cfb128;
const(EVP_CIPHER)* EVP_aes_128_ofb();
const(EVP_CIPHER)* EVP_aes_128_ctr();
const(EVP_CIPHER)* EVP_aes_128_ccm();
const(EVP_CIPHER)* EVP_aes_128_gcm();
const(EVP_CIPHER)* EVP_aes_128_xts();
const(EVP_CIPHER)* EVP_aes_192_ecb();
const(EVP_CIPHER)* EVP_aes_192_cbc();
const(EVP_CIPHER)* EVP_aes_192_cfb1();
const(EVP_CIPHER)* EVP_aes_192_cfb8();
const(EVP_CIPHER)* EVP_aes_192_cfb128();
alias EVP_aes_192_cfb = EVP_aes_192_cfb128;
const(EVP_CIPHER)* EVP_aes_192_ofb();
const(EVP_CIPHER)* EVP_aes_192_ctr();
const(EVP_CIPHER)* EVP_aes_192_ccm();
const(EVP_CIPHER)* EVP_aes_192_gcm();
const(EVP_CIPHER)* EVP_aes_256_ecb();
const(EVP_CIPHER)* EVP_aes_256_cbc();
const(EVP_CIPHER)* EVP_aes_256_cfb1();
const(EVP_CIPHER)* EVP_aes_256_cfb8();
const(EVP_CIPHER)* EVP_aes_256_cfb128();
alias EVP_aes_256_cfb = EVP_aes_256_cfb128;
const(EVP_CIPHER)* EVP_aes_256_ofb();
const(EVP_CIPHER)* EVP_aes_256_ctr();
const(EVP_CIPHER)* EVP_aes_256_ccm();
const(EVP_CIPHER)* EVP_aes_256_gcm();
const(EVP_CIPHER)* EVP_aes_256_xts();
version(OPENSSL_NO_SHA) {} else version(OPENSSL_NO_SHA1) {} else {
const(EVP_CIPHER)* EVP_aes_128_cbc_hmac_sha1();
const(EVP_CIPHER)* EVP_aes_256_cbc_hmac_sha1();
}
}
version(OPENSSL_NO_CAMELLIA) {} else {
const(EVP_CIPHER)* EVP_camellia_128_ecb();
const(EVP_CIPHER)* EVP_camellia_128_cbc();
const(EVP_CIPHER)* EVP_camellia_128_cfb1();
const(EVP_CIPHER)* EVP_camellia_128_cfb8();
const(EVP_CIPHER)* EVP_camellia_128_cfb128();
alias EVP_camellia_128_cfb = EVP_camellia_128_cfb128;
const(EVP_CIPHER)* EVP_camellia_128_ofb();
const(EVP_CIPHER)* EVP_camellia_128_ctr();
const(EVP_CIPHER)* EVP_camellia_192_ecb();
const(EVP_CIPHER)* EVP_camellia_192_cbc();
const(EVP_CIPHER)* EVP_camellia_192_cfb1();
const(EVP_CIPHER)* EVP_camellia_192_cfb8();
const(EVP_CIPHER)* EVP_camellia_192_cfb128();
alias EVP_camellia_192_cfb = EVP_camellia_192_cfb128;
const(EVP_CIPHER)* EVP_camellia_192_ofb();
const(EVP_CIPHER)* EVP_camellia_192_ctr();
const(EVP_CIPHER)* EVP_camellia_256_ecb();
const(EVP_CIPHER)* EVP_camellia_256_cbc();
const(EVP_CIPHER)* EVP_camellia_256_cfb1();
const(EVP_CIPHER)* EVP_camellia_256_cfb8();
const(EVP_CIPHER)* EVP_camellia_256_cfb128();
alias EVP_camellia_256_cfb = EVP_camellia_256_cfb128;
const(EVP_CIPHER)* EVP_camellia_256_ofb();
const(EVP_CIPHER)* EVP_camellia_256_ctr();
}

const(EVP_CIPHER)* EVP_chacha20();
const(EVP_CIPHER)* EVP_chacha20_poly1305();

version(OPENSSL_NO_SEED) {} else {
const(EVP_CIPHER)* EVP_seed_ecb();
const(EVP_CIPHER)* EVP_seed_cbc();
const(EVP_CIPHER)* EVP_seed_cfb128();
alias EVP_seed_cfb = EVP_seed_cfb128;
const(EVP_CIPHER)* EVP_seed_ofb();
}

void OPENSSL_add_all_algorithms_noconf();
void OPENSSL_add_all_algorithms_conf();

version (OPENSSL_LOAD_CONF) {
alias OpenSSL_add_all_algorithms = OPENSSL_add_all_algorithms_conf;
} else {
alias OpenSSL_add_all_algorithms = OPENSSL_add_all_algorithms_noconf;
}

static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
{
    void OpenSSL_add_all_ciphers();
    void OpenSSL_add_all_digests();
}
else
{
    auto OpenSSL_add_all_ciphers() ()
    {
        return OPENSSL_INIT_crypto_library_start(OPENSSL_INIT_ADD_ALL_CIPHERS, null);
    }
    auto OpenSSL_add_all_digests() ()
    {
        return OPENSSL_INIT_crypto_library_start(OPENSSL_INIT_ADD_ALL_DIGESTS, null);
    }
}

int EVP_add_cipher(const(EVP_CIPHER)* cipher);
int EVP_add_digest(const(EVP_MD)* digest);

const(EVP_CIPHER)* EVP_get_cipherbyname(const(char)* name);
const(EVP_MD)* EVP_get_digestbyname(const(char)* name);
static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
    void EVP_cleanup();
else
    void EVP_cleanup()() {}

void EVP_CIPHER_do_all(ExternC!(void function(const(EVP_CIPHER)* ciph,
		const(char)* from, const(char)* to, void* x)) fn, void* arg);
void EVP_CIPHER_do_all_sorted(ExternC!(void function(const(EVP_CIPHER)* ciph,
		const(char)* from, const(char)* to, void* x)) fn, void* arg);

void EVP_MD_do_all(ExternC!(void function(const(EVP_MD)* ciph,
		const(char)* from, const(char)* to, void* x)) fn, void* arg);
void EVP_MD_do_all_sorted(ExternC!(void function(const(EVP_MD)* ciph,
		const(char)* from, const(char)* to, void* x)) fn, void* arg);

int		EVP_PKEY_decrypt_old(ubyte* dec_key,
			const(ubyte)* enc_key,int enc_key_len,
			EVP_PKEY* private_key);
int		EVP_PKEY_encrypt_old(ubyte* enc_key,
			const(ubyte)* key,int key_len,
			EVP_PKEY* pub_key);
int		EVP_PKEY_type(int type);
static if (OPENSSL_VERSION_BEFORE(3, 0, 0)) {
	int		EVP_PKEY_id(const(EVP_PKEY)* pkey);
	int		EVP_PKEY_base_id(const(EVP_PKEY)* pkey);
} else {
	int		EVP_PKEY_get_id(const(EVP_PKEY)* pkey);
	alias 	EVP_PKEY_id = EVP_PKEY_get_id;
	
	int		EVP_PKEY_get_base_id(const(EVP_PKEY)* pkey);
	alias 	EVP_PKEY_base_id = EVP_PKEY_get_base_id;
}
int		EVP_PKEY_bits(EVP_PKEY* pkey);
int		EVP_PKEY_size(EVP_PKEY* pkey);
int 		EVP_PKEY_set_type(EVP_PKEY* pkey,int type);
int		EVP_PKEY_set_type_str(EVP_PKEY* pkey, const(char)* str, int len);
int 		EVP_PKEY_assign(EVP_PKEY* pkey,int type,void* key);
void* 		EVP_PKEY_get0(EVP_PKEY* pkey);
const(ubyte)* EVP_PKEY_get0_hmac(const(EVP_PKEY)* pkey, size_t* len);

version(OPENSSL_NO_RSA) {} else {
import deimos.openssl.rsa;
int EVP_PKEY_set1_RSA(EVP_PKEY* pkey, RSA* key);
RSA* EVP_PKEY_get1_RSA(EVP_PKEY* pkey);
}
version(OPENSSL_NO_DSA) {} else {
import deimos.openssl.dsa; /*struct dsa_st;*/
int EVP_PKEY_set1_DSA(EVP_PKEY* pkey,dsa_st* key);
dsa_st* EVP_PKEY_get1_DSA(EVP_PKEY* pkey);
}
version(OPENSSL_NO_DH) {} else {
import deimos.openssl.dh; /*struct dh_st;*/
int EVP_PKEY_set1_DH(EVP_PKEY* pkey,dh_st* key);
dh_st* EVP_PKEY_get1_DH(EVP_PKEY* pkey);
}
version(OPENSSL_NO_EC) {} else {
struct ec_key_st;
int EVP_PKEY_set1_EC_KEY(EVP_PKEY* pkey,ec_key_st* key);
ec_key_st* EVP_PKEY_get1_EC_KEY(EVP_PKEY* pkey);
}

EVP_PKEY* 	EVP_PKEY_new();
int EVP_PKEY_up_ref(EVP_PKEY* pkey);
void		EVP_PKEY_free(EVP_PKEY* pkey);

EVP_PKEY* 	d2i_PublicKey(int type,EVP_PKEY** a, const(ubyte)** pp,
			c_long length);
int		i2d_PublicKey(EVP_PKEY* a, ubyte** pp);

EVP_PKEY* 	d2i_PrivateKey(int type,EVP_PKEY** a, const(ubyte)** pp,
			c_long length);
EVP_PKEY* 	d2i_AutoPrivateKey(EVP_PKEY** a, const(ubyte)** pp,
			c_long length);
int		i2d_PrivateKey(EVP_PKEY* a, ubyte** pp);

int EVP_PKEY_copy_parameters(EVP_PKEY* to, const(EVP_PKEY)* from);
int EVP_PKEY_missing_parameters(const(EVP_PKEY)* pkey);
int EVP_PKEY_save_parameters(EVP_PKEY* pkey,int mode);
int EVP_PKEY_cmp_parameters(const(EVP_PKEY)* a, const(EVP_PKEY)* b);

int EVP_PKEY_cmp(const(EVP_PKEY)* a, const(EVP_PKEY)* b);

int EVP_PKEY_print_public(BIO* out_, const(EVP_PKEY)* pkey,
				int indent, ASN1_PCTX* pctx);
int EVP_PKEY_print_private(BIO* out_, const(EVP_PKEY)* pkey,
				int indent, ASN1_PCTX* pctx);
int EVP_PKEY_print_params(BIO* out_, const(EVP_PKEY)* pkey,
				int indent, ASN1_PCTX* pctx);

int EVP_PKEY_get_default_digest_nid(EVP_PKEY* pkey, int* pnid);

int EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY* pkey,
	const(ubyte)* pt, size_t ptlen);
size_t EVP_PKEY_get1_tls_encodedpoint(EVP_PKEY* pkey, ubyte** ppt);

int EVP_CIPHER_type(const(EVP_CIPHER)* ctx);

/* calls methods */
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX* c, ASN1_TYPE* type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX* c, ASN1_TYPE* type);

/* These are used by EVP_CIPHER methods */
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX* c,ASN1_TYPE* type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX* c,ASN1_TYPE* type);

/* PKCS5 password based encryption */
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX* ctx, const(char)* pass, int passlen,
			 ASN1_TYPE* param, const(EVP_CIPHER)* cipher, const(EVP_MD)* md,
			 int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const(char)* pass, int passlen,
			   const(ubyte)* salt, int saltlen, int iter,
			   int keylen, ubyte* out_);
int PKCS5_PBKDF2_HMAC(const(char)* pass, int passlen,
			   const(ubyte)* salt, int saltlen, int iter,
			   const(EVP_MD)* digest,
		      int keylen, ubyte* out_);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX* ctx, const(char)* pass, int passlen,
			 ASN1_TYPE* param, const(EVP_CIPHER)* cipher, const(EVP_MD)* md,
			 int en_de);

int EVP_PBE_scrypt(const(char)* pass, size_t passlen,
                   const(ubyte)* salt, size_t saltlen,
                   ulong N, ulong r, ulong p, ulong maxmem,
                   ubyte* key, size_t keylen);

int PKCS5_v2_scrypt_keyivgen(EVP_CIPHER_CTX* ctx, const(char)* pass,
                             int passlen, ASN1_TYPE* param,
                             const(EVP_CIPHER)* c, const(EVP_MD)* md, int en_de);

void PKCS5_PBE_add();

int EVP_PBE_CipherInit (ASN1_OBJECT* pbe_obj, const(char)* pass, int passlen,
	     ASN1_TYPE* param, EVP_CIPHER_CTX* ctx, int en_de);

/* PBE type */

/* Can appear as the outermost AlgorithmIdentifier */
enum EVP_PBE_TYPE_OUTER = 0x0;
/* Is an PRF type OID */
enum EVP_PBE_TYPE_PRF = 0x1;
/* Is a PKCS#5 v2.0 KDF */
enum EVP_PBE_TYPE_KDF = 0x2;

int EVP_PBE_alg_add_type(int pbe_type, int pbe_nid, int cipher_nid, int md_nid,
	     EVP_PBE_KEYGEN* keygen);
int EVP_PBE_alg_add(int nid, const(EVP_CIPHER)* cipher, const(EVP_MD)* md,
		    EVP_PBE_KEYGEN* keygen);
int EVP_PBE_find(int type, int pbe_nid,
			int* pcnid, int* pmnid, EVP_PBE_KEYGEN** pkeygen);
void EVP_PBE_cleanup();
int EVP_PBE_get(int* ptype, int* ppbe_nid, size_t num);

enum ASN1_PKEY_ALIAS = 0x1;
enum ASN1_PKEY_DYNAMIC = 0x2;
enum ASN1_PKEY_SIGPARAM_NULL = 0x4;

enum ASN1_PKEY_CTRL_PKCS7_SIGN = 0x1;
enum ASN1_PKEY_CTRL_PKCS7_ENCRYPT = 0x2;
enum ASN1_PKEY_CTRL_DEFAULT_MD_NID = 0x3;
enum ASN1_PKEY_CTRL_CMS_SIGN = 0x5;
enum ASN1_PKEY_CTRL_CMS_ENVELOPE = 0x7;
enum ASN1_PKEY_CTRL_CMS_RI_TYPE = 0x8;

enum ASN1_PKEY_CTRL_SET1_TLS_ENCPT = 0x9;
enum ASN1_PKEY_CTRL_GET1_TLS_ENCPT = 0xa;

int EVP_PKEY_asn1_get_count();
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_get0(int idx);
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_find(ENGINE** pe, int type);
const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_asn1_find_str(ENGINE** pe,
					const(char)* str, int len);
int EVP_PKEY_asn1_add0(const(EVP_PKEY_ASN1_METHOD)* ameth);
int EVP_PKEY_asn1_add_alias(int to, int from);
int EVP_PKEY_asn1_get0_info(int* ppkey_id, int* pkey_base_id, int* ppkey_flags,
				const(char)** pinfo, const(char)** ppem_str,
					const(EVP_PKEY_ASN1_METHOD)* ameth);

const(EVP_PKEY_ASN1_METHOD)* EVP_PKEY_get0_asn1(const(EVP_PKEY)* pkey);
EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id, int flags,
					const(char)* pem_str, const(char)* info);
void EVP_PKEY_asn1_copy(EVP_PKEY_ASN1_METHOD* dst,
			const(EVP_PKEY_ASN1_METHOD)* src);
void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD* ameth);
void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD* ameth,
		ExternC!(int function(EVP_PKEY* pk, X509_PUBKEY* pub)) pub_decode,
		ExternC!(int function(X509_PUBKEY* pub, const(EVP_PKEY)* pk)) pub_encode,
		ExternC!(int function(const(EVP_PKEY)* a, const(EVP_PKEY)* b)) pub_cmp,
		ExternC!(int function(BIO* out_, const(EVP_PKEY)* pkey, int indent,
							ASN1_PCTX* pctx)) pub_print,
		ExternC!(int function(const(EVP_PKEY)* pk)) pkey_size,
		ExternC!(int function(const(EVP_PKEY)* pk)) pkey_bits);
void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD* ameth,
		ExternC!(int function(EVP_PKEY* pk, const(PKCS8_PRIV_KEY_INFO)* p8inf)) priv_decode,
		ExternC!(int function(PKCS8_PRIV_KEY_INFO* p8, const(EVP_PKEY)* pk)) priv_encode,
		ExternC!(int function(BIO* out_, const(EVP_PKEY)* pkey, int indent,
							ASN1_PCTX* pctx)) priv_print);
void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD* ameth,
		ExternC!(int function(EVP_PKEY* pkey,
				const(ubyte)** pder, int derlen)) param_decode,
		ExternC!(int function(const(EVP_PKEY)* pkey, ubyte** pder)) param_encode,
		ExternC!(int function(const(EVP_PKEY)* pk)) param_missing,
		ExternC!(int function(EVP_PKEY* to, const(EVP_PKEY)* from)) param_copy,
		ExternC!(int function(const(EVP_PKEY)* a, const(EVP_PKEY)* b)) param_cmp,
		ExternC!(int function(BIO* out_, const(EVP_PKEY)* pkey, int indent,
							ASN1_PCTX* pctx)) param_print);

void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD* ameth,
		ExternC!(void function(EVP_PKEY* pkey)) pkey_free);
void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD* ameth,
		ExternC!(int function(EVP_PKEY* pkey, int op,
							c_long arg1, void* arg2)) pkey_ctrl);

private alias EVP_PKEY_asn1_item_verify_fn = int function(EVP_MD_CTX* ctx,
	const(ASN1_ITEM)* it, void* asn, X509_ALGOR* a, ASN1_BIT_STRING* sig, EVP_PKEY* pkey);
private alias EVP_PKEY_asn1_item_sign_fn = int function(EVP_MD_CTX* ctx,
	const(ASN1_ITEM)* it, void* asn, X509_ALGOR* alg1, X509_ALGOR* alg2, ASN1_BIT_STRING* sig);
void EVP_PKEY_asn1_set_item(EVP_PKEY_ASN1_METHOD* ameth,
	EVP_PKEY_asn1_item_verify_fn item_verify, EVP_PKEY_asn1_item_sign_fn item_sign);

private alias EVP_PKEY_asn1_security_bit_fn = int function(const(EVP_PKEY)* pk);
void EVP_PKEY_asn1_set_security_bits(EVP_PKEY_ASN1_METHOD* ameth,
	EVP_PKEY_asn1_security_bit_fn pkey_security_bits);

enum EVP_PKEY_OP_UNDEFINED = 0;
enum EVP_PKEY_OP_PARAMGEN = (1<<1);
enum EVP_PKEY_OP_KEYGEN = (1<<2);
enum EVP_PKEY_OP_SIGN = (1<<3);
enum EVP_PKEY_OP_VERIFY = (1<<4);
enum EVP_PKEY_OP_VERIFYRECOVER = (1<<5);
enum EVP_PKEY_OP_SIGNCTX = (1<<6);
enum EVP_PKEY_OP_VERIFYCTX = (1<<7);
enum EVP_PKEY_OP_ENCRYPT = (1<<8);
enum EVP_PKEY_OP_DECRYPT = (1<<9);
enum EVP_PKEY_OP_DERIVE = (1<<10);

enum EVP_PKEY_OP_TYPE_SIG =
	(EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY | EVP_PKEY_OP_VERIFYRECOVER
		| EVP_PKEY_OP_SIGNCTX | EVP_PKEY_OP_VERIFYCTX);

enum EVP_PKEY_OP_TYPE_CRYPT =
	(EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT);

/+ BUG in original headers: EVP_PKEY_OP_SIG, EVP_PKEY_OP_CRYPT are not defined.
enum EVP_PKEY_OP_TYPE_NOGEN =
	(EVP_PKEY_OP_SIG | EVP_PKEY_OP_CRYPT | EVP_PKEY_OP_DERIVE);
+/

enum EVP_PKEY_OP_TYPE_GEN =
		(EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN);

auto EVP_PKEY_CTX_set_signature_md()(EVP_PKEY_CTX* ctx, void* md) {
	return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_TYPE_SIG,
				EVP_PKEY_CTRL_MD, 0, md);
}

auto EVP_PKEY_CTX_set_mac_key()(EVP_PKEY_CTX* ctx, ubyte* key, int len) {
	return EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
		EVP_PKEY_CTRL_SET_MAC_KEY, len, key);
}

enum EVP_PKEY_CTRL_MD = 1;
enum EVP_PKEY_CTRL_PEER_KEY = 2;

enum EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
enum EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;

enum EVP_PKEY_CTRL_PKCS7_SIGN = 5;

enum EVP_PKEY_CTRL_SET_MAC_KEY = 6;

enum EVP_PKEY_CTRL_DIGESTINIT = 7;

/* Used by GOST key encryption in TLS */
enum EVP_PKEY_CTRL_SET_IV = 8;

enum EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
enum EVP_PKEY_CTRL_CMS_DECRYPT = 10;
enum EVP_PKEY_CTRL_CMS_SIGN = 11;

enum EVP_PKEY_CTRL_CIPHER = 12;

enum EVP_PKEY_ALG_CTRL = 0x1000;


enum EVP_PKEY_FLAG_AUTOARGLEN = 2;
/* Method handles all operations: don't assume any digest related
 * defaults.
 */
enum EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;

const(EVP_PKEY_METHOD)* EVP_PKEY_meth_find(int type);
EVP_PKEY_METHOD* EVP_PKEY_meth_new(int id, int flags);
void EVP_PKEY_meth_get0_info(int* ppkey_id, int* pflags,
				const(EVP_PKEY_METHOD)* meth);
void EVP_PKEY_meth_copy(EVP_PKEY_METHOD* dst, const(EVP_PKEY_METHOD)* src);
void EVP_PKEY_meth_free(EVP_PKEY_METHOD* pmeth);
int EVP_PKEY_meth_add0(const(EVP_PKEY_METHOD)* pmeth);

EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY* pkey, ENGINE* e);
EVP_PKEY_CTX* EVP_PKEY_CTX_new_id(int id, ENGINE* e);
EVP_PKEY_CTX* EVP_PKEY_CTX_dup(EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX* ctx);

int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX* ctx, int keytype, int optype,
				int cmd, int p1, void* p2);
int EVP_PKEY_CTX_ctrl_str(EVP_PKEY_CTX* ctx, const(char)* type,
						const(char)* value);
int EVP_PKEY_CTX_ctrl_uint64(EVP_PKEY_CTX* ctx, int keytype, int optype,
                             int cmd, ulong value);

int EVP_PKEY_CTX_get_operation(EVP_PKEY_CTX* ctx);
void EVP_PKEY_CTX_set0_keygen_info(EVP_PKEY_CTX* ctx, int* dat, int datlen);

EVP_PKEY* EVP_PKEY_new_mac_key(int type, ENGINE* e,
				const(ubyte)* key, int keylen);

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
{
    EVP_PKEY* EVP_PKEY_new_raw_private_key(
        int type, ENGINE* e, const(ubyte)* priv, size_t len);
    EVP_PKEY* EVP_PKEY_new_raw_public_key(
        int type, ENGINE* e, const(ubyte)* pub, size_t len);
    int EVP_PKEY_get_raw_private_key(
        const(EVP_PKEY)* pkey, ubyte* priv, size_t* len);
    int EVP_PKEY_get_raw_public_key(
        const(EVP_PKEY)* pkey, ubyte* pub, size_t* len);
}

void EVP_PKEY_CTX_set_data(EVP_PKEY_CTX* ctx, void* data);
void* EVP_PKEY_CTX_get_data(EVP_PKEY_CTX* ctx);
EVP_PKEY* EVP_PKEY_CTX_get0_pkey(EVP_PKEY_CTX* ctx);

EVP_PKEY* EVP_PKEY_CTX_get0_peerkey(EVP_PKEY_CTX* ctx);

void EVP_PKEY_CTX_set_app_data(EVP_PKEY_CTX* ctx, void* data);
void* EVP_PKEY_CTX_get_app_data(EVP_PKEY_CTX* ctx);

int EVP_PKEY_sign_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_sign(EVP_PKEY_CTX* ctx,
			ubyte* sig, size_t* siglen,
			const(ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify(EVP_PKEY_CTX* ctx,
			const(ubyte)* sig, size_t siglen,
			const(ubyte)* tbs, size_t tbslen);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX* ctx,
			ubyte* rout, size_t* routlen,
			const(ubyte)* sig, size_t siglen);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX* ctx,
			ubyte* out_, size_t* outlen,
			const(ubyte)* in_, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX* ctx,
			ubyte* out_, size_t* outlen,
			const(ubyte)* in_, size_t inlen);

static if (OPENSSL_VERSION_AT_LEAST(3, 0, 0))
    int EVP_PKEY_derive_init_ex(EVP_PKEY_CTX* ctx, EVP_KEYEXCH* exchange);
int EVP_PKEY_derive_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX* ctx, EVP_PKEY* peer);
int EVP_PKEY_derive(EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);

alias EVP_PKEY_gen_cb = typeof(*(ExternC!(int function(EVP_PKEY_CTX* ctx))).init);

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_paramgen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);

void EVP_PKEY_CTX_set_cb(EVP_PKEY_CTX* ctx, EVP_PKEY_gen_cb* cb);
EVP_PKEY_gen_cb* EVP_PKEY_CTX_get_cb(EVP_PKEY_CTX* ctx);

int EVP_PKEY_CTX_get_keygen_info(EVP_PKEY_CTX* ctx, int idx);

void EVP_PKEY_meth_set_init(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) init);

void EVP_PKEY_meth_set_copy(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* dst, EVP_PKEY_CTX* src)) copy);

void EVP_PKEY_meth_set_cleanup(EVP_PKEY_METHOD* pmeth,
	ExternC!(void function(EVP_PKEY_CTX* ctx)) cleanup);

void EVP_PKEY_meth_set_paramgen(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) paramgen_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)) paramgen);

void EVP_PKEY_meth_set_keygen(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) keygen_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey)) keygen);

void EVP_PKEY_meth_set_sign(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) sign_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen,
					const(ubyte)* tbs, size_t tbslen)) sign);

void EVP_PKEY_meth_set_verify(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) verify_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, const(ubyte)* sig, size_t siglen,
					const(ubyte)* tbs, size_t tbslen)) verify);

void EVP_PKEY_meth_set_verify_recover(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) verify_recover_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx,
					ubyte* sig, size_t* siglen,
					const(ubyte)* tbs, size_t tbslen)) verify_recover);

void EVP_PKEY_meth_set_signctx(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx)) signctx_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen,
					EVP_MD_CTX* mctx)) signctx);

void EVP_PKEY_meth_set_verifyctx(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx)) verifyctx_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, const(ubyte)* sig,int siglen,
					EVP_MD_CTX* mctx)) verifyctx);

void EVP_PKEY_meth_set_encrypt(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) encrypt_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen,
					const(ubyte)* in_, size_t inlen)) encryptfn);

void EVP_PKEY_meth_set_decrypt(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) decrypt_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen,
					const(ubyte)* in_, size_t inlen)) decrypt);

void EVP_PKEY_meth_set_derive(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx)) derive_init,
	ExternC!(int function(EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen)) derive);

void EVP_PKEY_meth_set_ctrl(EVP_PKEY_METHOD* pmeth,
	ExternC!(int function(EVP_PKEY_CTX* ctx, int type, int p1, void* p2)) ctrl,
	ExternC!(int function(EVP_PKEY_CTX* ctx,
					const(char)* type, const(char)* value)) ctrl_str);

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
{
    private alias EVP_PKEY_meth_digestsign_fn = int function(
        EVP_MD_CTX* ctx, ubyte* sig, size_t* siglen, const(ubyte)* tbs, size_t tbslen);
    private alias EVP_PKEY_meth_digestverify_fn = int function(
        EVP_MD_CTX*ctx, const(ubyte)* sig, size_t siglen, const(ubyte)* tbs, size_t tbslen);

    void EVP_PKEY_meth_set_digestsign(
        EVP_PKEY_METHOD* pmeth, EVP_PKEY_meth_digestsign_fn digestsign);
    void EVP_PKEY_meth_set_digestverify(
        EVP_PKEY_METHOD* pmeth, EVP_PKEY_meth_digestverify_fn digestverify);
    void EVP_PKEY_meth_get_digestsign(
        EVP_PKEY_METHOD *pmeth, EVP_PKEY_meth_digestsign_fn* digestsign);
    void EVP_PKEY_meth_get_digestverify(
        EVP_PKEY_METHOD *pmeth, EVP_PKEY_meth_digestverify_fn* digestverify);
}

static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
{
    private alias EVP_PKEY_meth_lifetime_fn = int function(EVP_PKEY_CTX* ctx);
    private alias EVP_PKEY_meth_lifetime2_fn = int function(EVP_PKEY_CTX* ctx, EVP_MD_CTX* mctx);

    private alias EVP_PKEY_meth_copy_fn = int function (EVP_PKEY_CTX* dst, EVP_PKEY_CTX* src);
    private alias EVP_PKEY_meth_gen_fn = int function(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey);
    private alias EVP_PKEY_meth_sign_fn = int function(
        EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const(ubyte)* tbs, size_t tbslen);
    private alias EVP_PKEY_meth_verify_fn = int function(
        EVP_PKEY_CTX* ctx, const(ubyte)* sig, size_t siglen, const(ubyte)* tbs, size_t tbslen);
    private alias EVP_PKEY_meth_verify_recover_fn = int function(
        EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, const(ubyte)* tbs, size_t tbslen);
    private alias EVP_PKEY_meth_signctx_fn = int function(
        EVP_PKEY_CTX* ctx, ubyte* sig, size_t* siglen, EVP_MD_CTX* mctx);
    private alias EVP_PKEY_meth_verifyctx_fn = int function(
        EVP_PKEY_CTX* ctx, const(ubyte)* sig, int siglen, EVP_MD_CTX* mctx);
    private alias EVP_PKEY_meth_encrypt_fn = int function(
        EVP_PKEY_CTX *ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);
    private alias EVP_PKEY_meth_decrypt_fn = int function(
        EVP_PKEY_CTX* ctx, ubyte* out_, size_t* outlen, const(ubyte)* in_, size_t inlen);
    private alias EVP_PKEY_meth_derive_fn = int function(
        EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);
    private alias EVP_PKEY_meth_ctrl_fn = int function(
        EVP_PKEY_CTX* ctx, int type, int p1, void* p2);
    private alias EVP_PKEY_meth_ctrl_str_fn = int function(
        EVP_PKEY_CTX* ctx, const(char)* type, const(char)* value);

    void EVP_PKEY_meth_get_init(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pinit);

    void EVP_PKEY_meth_get_copy(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_copy_fn* pcopy);

    void EVP_PKEY_meth_get_cleanup(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pcleanup);

    void EVP_PKEY_meth_get_paramgen(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pparamgen_init,
        EVP_PKEY_meth_gen_fn* pparamgen);

    void EVP_PKEY_meth_get_keygen(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pkeygen_init,
        EVP_PKEY_meth_gen_fn* pkeygen);

    void EVP_PKEY_meth_get_sign(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* psign_init,
        EVP_PKEY_meth_sign_fn* psign);

    void EVP_PKEY_meth_get_verify(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pverify_init,
        EVP_PKEY_meth_verify_fn* pverify);

    void EVP_PKEY_meth_get_verify_recover(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pverify_recover_init,
        EVP_PKEY_meth_verify_recover_fn* pverify_recover);

    void EVP_PKEY_meth_get_signctx(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime2_fn* psignctx_init,
        EVP_PKEY_meth_signctx_fn* psignctx);

    void EVP_PKEY_meth_get_verifyctx(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime2_fn* pverifyctx_init,
        EVP_PKEY_meth_verifyctx_fn* pverifyctx);

    void EVP_PKEY_meth_get_encrypt(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pencrypt_init,
        EVP_PKEY_meth_encrypt_fn* pencryptfn);

    void EVP_PKEY_meth_get_decrypt(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pdecrypt_init,
        EVP_PKEY_meth_decrypt_fn* pdecrypt);

    void EVP_PKEY_meth_get_derive(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_lifetime_fn* pderive_init,
        EVP_PKEY_meth_derive_fn* pderive);

    void EVP_PKEY_meth_get_ctrl(
        const(EVP_PKEY_METHOD)* pmeth, EVP_PKEY_meth_ctrl_fn* pctrl,
        EVP_PKEY_meth_ctrl_str_fn* pctrl_str);
}

static if (OPENSSL_VERSION_AT_LEAST(3, 0, 0))
{
	void EVP_KEYEXCH_free(EVP_KEYEXCH* exchange);
	int EVP_KEYEXCH_up_ref(EVP_KEYEXCH* exchange);
	EVP_KEYEXCH* EVP_KEYEXCH_fetch(OSSL_LIB_CTX* ctx, const(char)* algorithm,
		const(char)* properties);
	OSSL_PROVIDER* EVP_KEYEXCH_get0_provider(const(EVP_KEYEXCH)* exchange);
	int EVP_KEYEXCH_is_a(const(EVP_KEYEXCH)* keyexch, const(char)* name);
	const(char)* EVP_KEYEXCH_get0_name(const(EVP_KEYEXCH)* keyexch);
	const(char)* EVP_KEYEXCH_get0_description(const(EVP_KEYEXCH)* keyexch);

	private alias EVP_KEYEXCH_apply_fn = void function(EVP_KEYEXCH* keyexch, void* data);
	private alias EVP_KEYEXCH_apply_names_fn = void function(const(char)* keyexch, void* data);
	void EVP_KEYEXCH_do_all_provided(
		OSSL_LIB_CTX* libctx, EVP_KEYEXCH_apply_fn fn, void* data);
	int EVP_KEYEXCH_names_do_all(
		const(EVP_KEYEXCH)* keyexch, EVP_KEYEXCH_apply_names_fn fn, void *data);
	const(OSSL_PARAM)* EVP_KEYEXCH_gettable_ctx_params(const(EVP_KEYEXCH)* keyexch);
	const(OSSL_PARAM)* EVP_KEYEXCH_settable_ctx_params(const(EVP_KEYEXCH)* keyexch);

	int EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX* ctx, const(char)* name);
	int EVP_PKEY_CTX_get_group_name(EVP_PKEY_CTX* ctx, char* name, size_t namelen);
	int EVP_PKEY_get_group_name(const(EVP_PKEY)* pkey, char* name, size_t name_sz,
		size_t* gname_len);

	OSSL_LIB_CTX* EVP_PKEY_CTX_get0_libctx(EVP_PKEY_CTX* ctx);
	const(char)* EVP_PKEY_CTX_get0_propq(const(EVP_PKEY_CTX)* ctx);
	const(OSSL_PROVIDER)* EVP_PKEY_CTX_get0_provider(const(EVP_PKEY_CTX)* ctx);
}

void EVP_add_alg_module();

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
static if (OPENSSL_VERSION_BEFORE(1, 1, 0))
    void ERR_load_EVP_strings();
else
    int ERR_load_EVP_strings();

/* Error codes for the EVP functions. */

/* Function codes. */
enum EVP_F_AESNI_INIT_KEY = 165;
enum EVP_F_AESNI_XTS_CIPHER = 176;
enum EVP_F_AES_INIT_KEY = 133;
enum EVP_F_AES_XTS = 172;
enum EVP_F_AES_XTS_CIPHER = 175;
enum EVP_F_ALG_MODULE_INIT = 177;
enum EVP_F_CAMELLIA_INIT_KEY = 159;
enum EVP_F_CMAC_INIT = 173;
enum EVP_F_D2I_PKEY = 100;
enum EVP_F_DO_SIGVER_INIT = 161;
enum EVP_F_DSAPKEY2PKCS8 = 134;
enum EVP_F_DSA_PKEY2PKCS8 = 135;
enum EVP_F_ECDSA_PKEY2PKCS8 = 129;
enum EVP_F_ECKEY_PKEY2PKCS8 = 132;
enum EVP_F_EVP_CIPHERINIT_EX = 123;
enum EVP_F_EVP_CIPHER_CTX_COPY = 163;
enum EVP_F_EVP_CIPHER_CTX_CTRL = 124;
enum EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 122;
enum EVP_F_EVP_DECRYPTFINAL_EX = 101;
enum EVP_F_EVP_DIGESTINIT_EX = 128;
enum EVP_F_EVP_ENCRYPTFINAL_EX = 127;
enum EVP_F_EVP_MD_CTX_COPY_EX = 110;
enum EVP_F_EVP_MD_SIZE = 162;
enum EVP_F_EVP_OPENINIT = 102;
enum EVP_F_EVP_PBE_ALG_ADD = 115;
enum EVP_F_EVP_PBE_ALG_ADD_TYPE = 160;
enum EVP_F_EVP_PBE_CIPHERINIT = 116;
enum EVP_F_EVP_PKCS82PKEY = 111;
enum EVP_F_EVP_PKCS82PKEY_BROKEN = 136;
enum EVP_F_EVP_PKEY2PKCS8_BROKEN = 113;
enum EVP_F_EVP_PKEY_COPY_PARAMETERS = 103;
enum EVP_F_EVP_PKEY_CTX_CTRL = 137;
enum EVP_F_EVP_PKEY_CTX_CTRL_STR = 150;
enum EVP_F_EVP_PKEY_CTX_DUP = 156;
enum EVP_F_EVP_PKEY_DECRYPT = 104;
enum EVP_F_EVP_PKEY_DECRYPT_INIT = 138;
enum EVP_F_EVP_PKEY_DECRYPT_OLD = 151;
enum EVP_F_EVP_PKEY_DERIVE = 153;
enum EVP_F_EVP_PKEY_DERIVE_INIT = 154;
enum EVP_F_EVP_PKEY_DERIVE_SET_PEER = 155;
enum EVP_F_EVP_PKEY_ENCRYPT = 105;
enum EVP_F_EVP_PKEY_ENCRYPT_INIT = 139;
enum EVP_F_EVP_PKEY_ENCRYPT_OLD = 152;
enum EVP_F_EVP_PKEY_GET1_DH = 119;
enum EVP_F_EVP_PKEY_GET1_DSA = 120;
enum EVP_F_EVP_PKEY_GET1_ECDSA = 130;
enum EVP_F_EVP_PKEY_GET1_EC_KEY = 131;
enum EVP_F_EVP_PKEY_GET1_RSA = 121;
enum EVP_F_EVP_PKEY_KEYGEN = 146;
enum EVP_F_EVP_PKEY_KEYGEN_INIT = 147;
enum EVP_F_EVP_PKEY_NEW = 106;
enum EVP_F_EVP_PKEY_PARAMGEN = 148;
enum EVP_F_EVP_PKEY_PARAMGEN_INIT = 149;
enum EVP_F_EVP_PKEY_SIGN = 140;
enum EVP_F_EVP_PKEY_SIGN_INIT = 141;
enum EVP_F_EVP_PKEY_VERIFY = 142;
enum EVP_F_EVP_PKEY_VERIFY_INIT = 143;
enum EVP_F_EVP_PKEY_VERIFY_RECOVER = 144;
enum EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 145;
enum EVP_F_EVP_RIJNDAEL = 126;
enum EVP_F_EVP_SIGNFINAL = 107;
enum EVP_F_EVP_VERIFYFINAL = 108;
enum EVP_F_FIPS_CIPHERINIT = 166;
enum EVP_F_FIPS_CIPHER_CTX_COPY = 170;
enum EVP_F_FIPS_CIPHER_CTX_CTRL = 167;
enum EVP_F_FIPS_CIPHER_CTX_SET_KEY_LENGTH = 171;
enum EVP_F_FIPS_DIGESTINIT = 168;
enum EVP_F_FIPS_MD_CTX_COPY = 169;
enum EVP_F_HMAC_INIT_EX = 174;
enum EVP_F_INT_CTX_NEW = 157;
enum EVP_F_PKCS5_PBE_KEYIVGEN = 117;
enum EVP_F_PKCS5_V2_PBE_KEYIVGEN = 118;
enum EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 164;
enum EVP_F_PKCS8_SET_BROKEN = 112;
enum EVP_F_PKEY_SET_TYPE = 158;
enum EVP_F_RC2_MAGIC_TO_METH = 109;
enum EVP_F_RC5_CTRL = 125;

/* Reason codes. */
enum EVP_R_AES_IV_SETUP_FAILED = 162;
enum EVP_R_AES_KEY_SETUP_FAILED = 143;
enum EVP_R_ASN1_LIB = 140;
enum EVP_R_BAD_BLOCK_LENGTH = 136;
enum EVP_R_BAD_DECRYPT = 100;
enum EVP_R_BAD_KEY_LENGTH = 137;
enum EVP_R_BN_DECODE_ERROR = 112;
enum EVP_R_BN_PUBKEY_ERROR = 113;
enum EVP_R_BUFFER_TOO_SMALL = 155;
enum EVP_R_CAMELLIA_KEY_SETUP_FAILED = 157;
enum EVP_R_CIPHER_PARAMETER_ERROR = 122;
enum EVP_R_COMMAND_NOT_SUPPORTED = 147;
enum EVP_R_CTRL_NOT_IMPLEMENTED = 132;
enum EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED = 133;
enum EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 138;
enum EVP_R_DECODE_ERROR = 114;
enum EVP_R_DIFFERENT_KEY_TYPES = 101;
enum EVP_R_DIFFERENT_PARAMETERS = 153;
enum EVP_R_DISABLED_FOR_FIPS = 163;
enum EVP_R_ENCODE_ERROR = 115;
enum EVP_R_ERROR_LOADING_SECTION = 165;
enum EVP_R_ERROR_SETTING_FIPS_MODE = 166;
enum EVP_R_EVP_PBE_CIPHERINIT_ERROR = 119;
enum EVP_R_EXPECTING_AN_RSA_KEY = 127;
enum EVP_R_EXPECTING_A_DH_KEY = 128;
enum EVP_R_EXPECTING_A_DSA_KEY = 129;
enum EVP_R_EXPECTING_A_ECDSA_KEY = 141;
enum EVP_R_EXPECTING_A_EC_KEY = 142;
enum EVP_R_FIPS_MODE_NOT_SUPPORTED = 167;
enum EVP_R_INITIALIZATION_ERROR = 134;
enum EVP_R_INPUT_NOT_INITIALIZED = 111;
enum EVP_R_INVALID_DIGEST = 152;
enum EVP_R_INVALID_FIPS_MODE = 168;
enum EVP_R_INVALID_KEY_LENGTH = 130;
enum EVP_R_INVALID_OPERATION = 148;
enum EVP_R_IV_TOO_LARGE = 102;
enum EVP_R_KEYGEN_FAILURE = 120;
enum EVP_R_MESSAGE_DIGEST_IS_NULL = 159;
enum EVP_R_METHOD_NOT_SUPPORTED = 144;
enum EVP_R_MISSING_PARAMETERS = 103;
enum EVP_R_NO_CIPHER_SET = 131;
enum EVP_R_NO_DEFAULT_DIGEST = 158;
enum EVP_R_NO_DIGEST_SET = 139;
enum EVP_R_NO_DSA_PARAMETERS = 116;
enum EVP_R_NO_KEY_SET = 154;
enum EVP_R_NO_OPERATION_SET = 149;
enum EVP_R_NO_SIGN_FUNCTION_CONFIGURED = 104;
enum EVP_R_NO_VERIFY_FUNCTION_CONFIGURED = 105;
enum EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE = 150;
enum EVP_R_OPERATON_NOT_INITIALIZED = 151;
enum EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE = 117;
enum EVP_R_PRIVATE_KEY_DECODE_ERROR = 145;
enum EVP_R_PRIVATE_KEY_ENCODE_ERROR = 146;
enum EVP_R_PUBLIC_KEY_NOT_RSA = 106;
enum EVP_R_TOO_LARGE = 164;
enum EVP_R_UNKNOWN_CIPHER = 160;
enum EVP_R_UNKNOWN_DIGEST = 161;
enum EVP_R_UNKNOWN_OPTION = 169;
enum EVP_R_UNKNOWN_PBE_ALGORITHM = 121;
enum EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS = 135;
enum EVP_R_UNSUPPORTED_ALGORITHM = 156;
enum EVP_R_UNSUPPORTED_CIPHER = 107;
enum EVP_R_UNSUPPORTED_KEYLENGTH = 123;
enum EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION = 124;
enum EVP_R_UNSUPPORTED_KEY_SIZE = 108;
enum EVP_R_UNSUPPORTED_PRF = 125;
enum EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM = 118;
enum EVP_R_UNSUPPORTED_SALT_TYPE = 126;
enum EVP_R_WRONG_FINAL_BLOCK_LENGTH = 109;
enum EVP_R_WRONG_PUBLIC_KEY_TYPE = 110;
