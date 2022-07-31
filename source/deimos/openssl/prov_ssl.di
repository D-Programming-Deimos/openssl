/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.prov_ssl;

import deimos.openssl.opensslv;

static if (OPENSSL_VERSION_AT_LEAST(3, 0, 0))
{
	/* SSL/TLS related defines useful to providers */

	enum SSL_MAX_MASTER_KEY_LENGTH = 48;

	enum SSL3_VERSION                    = 0x0300;
	enum TLS1_VERSION                    = 0x0301;
	enum TLS1_1_VERSION                  = 0x0302;
	enum TLS1_2_VERSION                  = 0x0303;
	enum TLS1_3_VERSION                  = 0x0304;
	enum DTLS1_VERSION                   = 0xFEFF;
	enum DTLS1_2_VERSION                 = 0xFEFD;
	enum DTLS1_BAD_VER                   = 0x0100;
}
