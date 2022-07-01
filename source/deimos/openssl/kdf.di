/*
 * Port of `<openssl/kdf.h>`
 *
 * This header was introduced in v1.1.0.
 *
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.	 You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
module deimos.openssl.kdf;

import deimos.openssl.evp;
import deimos.openssl.opensslv;
import deimos.openssl.types;

extern (C):
nothrow:

static if (OPENSSL_VERSION_AT_LEAST(3, 0, 0))
{
	int EVP_KDF_up_ref(EVP_KDF* kdf);
	void EVP_KDF_free(EVP_KDF* kdf);
	EVP_KDF* EVP_KDF_fetch(
		OSSL_LIB_CTX *libctx, const(char)* algorithm, const(char)* properties);

	EVP_KDF_CTX* EVP_KDF_CTX_new(EVP_KDF* kdf);
	void EVP_KDF_CTX_free(EVP_KDF_CTX* ctx);
	EVP_KDF_CTX* EVP_KDF_CTX_dup(const(EVP_KDF_CTX)* src);
	const(char)* EVP_KDF_get0_description(const(EVP_KDF)* kdf);
	int EVP_KDF_is_a(const(EVP_KDF)* kdf, const(char)* name);
	const(char)* EVP_KDF_get0_name(const(EVP_KDF)* kdf);
	const(OSSL_PROVIDER)* EVP_KDF_get0_provider(const(EVP_KDF)* kdf);
	const(EVP_KDF)* EVP_KDF_CTX_kdf(EVP_KDF_CTX* ctx);

	void EVP_KDF_CTX_reset(EVP_KDF_CTX* ctx);
	size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX* ctx);
	int EVP_KDF_derive(
		EVP_KDF_CTX* ctx, ubyte* key, size_t keylen, const(OSSL_PARAM)* params);
	int EVP_KDF_get_params(EVP_KDF* kdf, OSSL_PARAM* params);
	int EVP_KDF_CTX_get_params(EVP_KDF_CTX* ctx, OSSL_PARAM* params);
	int EVP_KDF_CTX_set_params(EVP_KDF_CTX* ctx, const(OSSL_PARAM)* params);
	const(OSSL_PARAM)* EVP_KDF_gettable_params(const(EVP_KDF)* kdf);
	const(OSSL_PARAM)* EVP_KDF_gettable_ctx_params(const(EVP_KDF)* kdf);
	const(OSSL_PARAM)* EVP_KDF_settable_ctx_params(const(EVP_KDF)* kdf);
	const(OSSL_PARAM)* EVP_KDF_CTX_gettable_params(EVP_KDF_CTX* ctx);
	const(OSSL_PARAM)* EVP_KDF_CTX_settable_params(EVP_KDF_CTX* ctx);

	private alias EVP_KDF_apply_fn = extern(C) void function(EVP_KDF* kdf, void* arg);
	void EVP_KDF_do_all_provided(OSSL_LIB_CTX *libctx, EVP_KDF_apply_fn fn, void* arg);
	private alias EVP_KDF_names_apply_fn = extern(C) void function(const(char)* name, void* data);
	int EVP_KDF_names_do_all(const(EVP_KDF)* kdf, EVP_KDF_names_apply_fn fn, void* data);
}

enum EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND = 0;
enum EVP_KDF_HKDF_MODE_EXTRACT_ONLY		  = 1;
enum EVP_KDF_HKDF_MODE_EXPAND_ONLY		  = 2;

enum EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV	   = 65;
enum EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI	   = 66;
enum EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV = 67;
enum EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI = 68;
enum EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV  = 69;
enum EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI  = 70;

/**** The legacy PKEY-based KDF API follows. ****/

enum EVP_PKEY_CTRL_TLS_MD				  = (EVP_PKEY_ALG_CTRL);
enum EVP_PKEY_CTRL_TLS_SECRET			  = (EVP_PKEY_ALG_CTRL + 1);
enum EVP_PKEY_CTRL_TLS_SEED				  = (EVP_PKEY_ALG_CTRL + 2);
enum EVP_PKEY_CTRL_HKDF_MD				  = (EVP_PKEY_ALG_CTRL + 3);
enum EVP_PKEY_CTRL_HKDF_SALT			  = (EVP_PKEY_ALG_CTRL + 4);
enum EVP_PKEY_CTRL_HKDF_KEY				  = (EVP_PKEY_ALG_CTRL + 5);
enum EVP_PKEY_CTRL_HKDF_INFO			  = (EVP_PKEY_ALG_CTRL + 6);
static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
{
	// https://github.com/openssl/openssl/commit/cefa762ee5c28359986c6af5bf4db4e901f75846
	enum EVP_PKEY_CTRL_HKDF_MODE			  = (EVP_PKEY_ALG_CTRL + 7);
	enum EVP_PKEY_CTRL_PASS					  = (EVP_PKEY_ALG_CTRL + 8);
	enum EVP_PKEY_CTRL_SCRYPT_SALT			  = (EVP_PKEY_ALG_CTRL + 9);
	enum EVP_PKEY_CTRL_SCRYPT_N				  = (EVP_PKEY_ALG_CTRL + 10);
	enum EVP_PKEY_CTRL_SCRYPT_R				  = (EVP_PKEY_ALG_CTRL + 11);
	enum EVP_PKEY_CTRL_SCRYPT_P				  = (EVP_PKEY_ALG_CTRL + 12);
	enum EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES	  = (EVP_PKEY_ALG_CTRL + 13);
}
else
{
	// https://github.com/openssl/openssl/blob/OpenSSL_1_1_0l/include/openssl/kdf.h#L59

	/* Error codes for the KDF functions. */
	int ERR_load_KDF_strings();

	/* Function codes. */
	enum KDF_F_PKEY_TLS1_PRF_CTRL_STR = 100;
	enum KDF_F_PKEY_TLS1_PRF_DERIVE	  = 101;

	/* Reason codes. */
	enum KDF_R_INVALID_DIGEST		  = 100;
	enum KDF_R_MISSING_PARAMETER	  = 101;
	enum KDF_R_VALUE_MISSING		  = 102;
}

alias EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
alias EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY		 = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
alias EVP_PKEY_HKDEF_MODE_EXPAND_ONLY		 = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

static if (OPENSSL_VERSION_AT_LEAST(3, 0, 0))
{
	// Before 3.0.0 those were macros
	int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX* ctx, const(EVP_MD)* md);
	int EVP_PKEY_CTX_set1_tls1_prf_secret(
		EVP_PKEY_CTX* pctx, const(ubyte)* sec, int seclen);
	int EVP_PKEY_CTX_add1_tls1_prf_seed(
		EVP_PKEY_CTX* pctx, const(ubyte)* seed, int seedlen);

	int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX* ctx, const(EVP_MD)* md);
	int EVP_PKEY_CTX_set1_hkdf_salt(
		EVP_PKEY_CTX* ctx, const(ubyte)* salt, int saltlen);
	int EVP_PKEY_CTX_set1_hkdf_key(
		EVP_PKEY_CTX* ctx, const(ubyte)* key, int keylen);
	int EVP_PKEY_CTX_add1_hkdf_info(
		EVP_PKEY_CTX* ctx, const(ubyte)* info, int infolen);

	int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX* ctx, int mode);
	alias EVP_PKEY_CTX_hkdf_mode = EVP_PKEY_CTX_set_hkdf_mode;

	int EVP_PKEY_CTX_set1_pbe_pass(EVP_PKEY_CTX* ctx, const(char)* pass, int passlen);

	int EVP_PKEY_CTX_set1_scrypt_salt(
		EVP_PKEY_CTX* ctx, const(ubyte)* salt, int saltlen);

	int EVP_PKEY_CTX_set_scrypt_N(EVP_PKEY_CTX* ctx, ulong n);
	int EVP_PKEY_CTX_set_scrypt_r(EVP_PKEY_CTX* ctx, ulong r);
	int EVP_PKEY_CTX_set_scrypt_p(EVP_PKEY_CTX* ctx, ulong p);

	int EVP_PKEY_CTX_set_scrypt_maxmem_bytes(EVP_PKEY_CTX* ctx, ulong maxmem_bytes);
}
else
{
	auto EVP_PKEY_CTX_set_tls1_prf_md () (EVP_PKEY_CTX* pctx, const(EVP_MD)* md)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_MD, 0, md);
	}

	auto EVP_PKEY_CTX_set1_tls1_prf_secret () (
		EVP_PKEY_CTX* pctx, const(ubyte)* sec, int seclen)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SECRET, seclen, sec);
	}

	auto EVP_PKEY_CTX_add1_tls1_prf_seed () (
		EVP_PKEY_CTX* pctx, const(ubyte)* seed, int seedlen)
	{
		return EVP_PKEY_CTX_ctrl(
			ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SEED, seedlen, seed);
	}

	auto EVP_PKEY_CTX_set_hkdf_md () (EVP_PKEY_CTX* pctx, const(EVP_MD)* md)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD, 0, cast(void*) md);
	}
	auto EVP_PKEY_CTX_set1_hkdf_salt () (
		EVP_PKEY_CTX* pctx, const(ubyte)* salt, int saltlen)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_SALT, saltlen, cast(void*) salt);
	}
	auto EVP_PKEY_CTX_set1_hkdf_key () (
		EVP_PKEY_CTX* pctx, const(ubyte)* key, int keylen)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_KEY, keylen, cast(void*) key);
	}
	auto EVP_PKEY_CTX_add1_hkdf_info () (
		EVP_PKEY_CTX* pctx, const(ubyte)* info, int infolen)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_INFO, infolen, cast(void*) info);
	}

	auto EVP_PKEY_CTX_hkdf_mode () (EVP_PKEY_CTX* pctx, int mode)
	{
		return EVP_PKEY_CTX_ctrl(
			pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MODE, mode, null);
	}

	static if (OPENSSL_VERSION_AT_LEAST(1, 1, 1))
	{
		auto EVP_PKEY_CTX_set1_pbe_pass ()
			(EVP_PKEY_CTX* pctx, const(char)* pass, int passlen)
		{
			return EVP_PKEY_CTX_ctrl(
				pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_PASS, passlen, pass);
		}

		auto EVP_PKEY_CTX_set1_scrypt_salt ()
			(EVP_PKEY_CTX* pctx, const(ubyte)* salt, int saltlen)
		{
			return EVP_PKEY_CTX_ctrl(
				pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_SALT, saltlen, salt);
		}

		auto EVP_PKEY_CTX_set_scrypt_N ()
			(EVP_PKEY_CTX* pctx, ulong n)
		{
			return EVP_PKEY_CTX_ctrl_uint64(
				pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, n);
		}

		auto EVP_PKEY_CTX_set_scrypt_r ()
			(EVP_PKEY_CTX* pctx, ulong n)
		{
			return EVP_PKEY_CTX_ctrl_uint64(
				pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_R, r);
		}

		auto EVP_PKEY_CTX_set_scrypt_p ()
			(EVP_PKEY_CTX* pctx, ulong n)
		{
			return EVP_PKEY_CTX_ctrl_uint64(
				pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_P, p);
		}

		auto EVP_PKEY_CTX_set_scrypt_maxmem_bytes ()
			(EVP_PKEY_CTX* pctx, ulong maxmem_bytes)
		{
			return EVP_PKEY_CTX_ctrl_uint64(
				pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, maxmem_bytes);
		}
	}
}
