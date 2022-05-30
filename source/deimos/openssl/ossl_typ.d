/**
 * The original <openssl/ossl_typ.h> was renamed to <openssl/types.h>
 *
 * Upstream provides a compatibility module, and so do we.
 * See PR https://github.com/openssl/openssl/pull/9333
 *
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
module deimos.openssl.ossl_typ;

public import deimos.openssl.types;
