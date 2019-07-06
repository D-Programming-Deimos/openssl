/*
 * Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

module deimos.openssl.x509v3;

import deimos.openssl._d_util;
import deimos.openssl.crypto : OPENSSL_buf2hexstr, OPENSSL_hexstr2buf;

public import deimos.openssl.bio;
public import deimos.openssl.x509;
public import deimos.openssl.conf;


extern (C):
nothrow:

alias stack_st_X509_NAME_ENTRY = STACK_OF!(X509_NAME_ENTRY);
alias stack_st_X509_EXTENSION = STACK_OF!(X509_EXTENSION);
alias lhash_st_CONF_VALUE = LHASH_OF!(CONF_VALUE);
alias stack_st_OPENSSL_STRING = STACK_OF!(OPENSSL_STRING);

/* Forward reference */

/* Useful typedefs */

alias X509V3_EXT_NEW = void* function ();
alias X509V3_EXT_FREE = void function (void*);
alias X509V3_EXT_D2I = void* function (void*, const(ubyte*)*, c_long);
alias X509V3_EXT_I2D = int function (void*, ubyte**);
struct stack_st_CONF_VALUE;
alias X509V3_EXT_I2V = stack_st_CONF_VALUE* function (
    const(v3_ext_method)* method,
    void* ext,
    stack_st_CONF_VALUE* extlist);
alias X509V3_EXT_V2I = void* function (
    const(v3_ext_method)* method,
    v3_ext_ctx* ctx,
    stack_st_CONF_VALUE* values);
alias X509V3_EXT_I2S = char* function (
    const(v3_ext_method)* method,
    void* ext);
alias X509V3_EXT_S2I = void* function (
    const(v3_ext_method)* method,
    v3_ext_ctx* ctx,
    const(char)* str);
alias X509V3_EXT_I2R = int function (
    const(v3_ext_method)* method,
    void* ext,
    BIO* out_,
    int indent);
alias X509V3_EXT_R2I = void* function (
    const(v3_ext_method)* method,
    v3_ext_ctx* ctx,
    const(char)* str);

/* V3 extension structure */

struct v3_ext_method
{
    int ext_nid;
    int ext_flags;
    /* If this is set the following four fields are ignored */
    ASN1_ITEM_EXP* it;
    /* Old style ASN1 calls */
    X509V3_EXT_NEW ext_new;
    X509V3_EXT_FREE ext_free;
    X509V3_EXT_D2I d2i;
    X509V3_EXT_I2D i2d;
    /* The following pair is used for string extensions */
    X509V3_EXT_I2S i2s;
    X509V3_EXT_S2I s2i;
    /* The following pair is used for multi-valued extensions */
    X509V3_EXT_I2V i2v;
    X509V3_EXT_V2I v2i;
    /* The following are used for raw extensions */
    X509V3_EXT_I2R i2r;
    X509V3_EXT_R2I r2i;
    void* usr_data; /* Any extension specific data */
}

struct X509V3_CONF_METHOD_st
{
    char* function (void* db, const(char)* section, const(char)* value) get_string;
    stack_st_CONF_VALUE* function (void* db, const(char)* section) get_section;
    void function (void* db, char* string) free_string;
    void function (void* db, stack_st_CONF_VALUE* section) free_section;
}

alias X509V3_CONF_METHOD = X509V3_CONF_METHOD_st;

/* Context specific info */
struct v3_ext_ctx
{
    int flags;
    X509* issuer_cert;
    X509* subject_cert;
    X509_REQ* subject_req;
    X509_CRL* crl;
    X509V3_CONF_METHOD* db_meth;
    void* db;
    /* Maybe more here */
}

enum CTX_TEST = 0x1;
enum X509V3_CTX_REPLACE = 0x2;

alias X509V3_EXT_METHOD = v3_ext_method;

struct stack_st_X509V3_EXT_METHOD;
alias sk_X509V3_EXT_METHOD_compfunc = int function (const(X509V3_EXT_METHOD*)* a, const(X509V3_EXT_METHOD*)* b);
alias sk_X509V3_EXT_METHOD_freefunc = void function (X509V3_EXT_METHOD* a);
alias sk_X509V3_EXT_METHOD_copyfunc = v3_ext_method* function (const(X509V3_EXT_METHOD)* a);
int sk_X509V3_EXT_METHOD_num (const(stack_st_X509V3_EXT_METHOD)* sk);
X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_value (const(stack_st_X509V3_EXT_METHOD)* sk, int idx);
stack_st_X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_new (sk_X509V3_EXT_METHOD_compfunc compare);
stack_st_X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_new_null ();
void sk_X509V3_EXT_METHOD_free (stack_st_X509V3_EXT_METHOD* sk);
void sk_X509V3_EXT_METHOD_zero (stack_st_X509V3_EXT_METHOD* sk);
X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_delete (stack_st_X509V3_EXT_METHOD* sk, int i);
X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_delete_ptr (stack_st_X509V3_EXT_METHOD* sk, X509V3_EXT_METHOD* ptr);
int sk_X509V3_EXT_METHOD_push (stack_st_X509V3_EXT_METHOD* sk, X509V3_EXT_METHOD* ptr);
int sk_X509V3_EXT_METHOD_unshift (stack_st_X509V3_EXT_METHOD* sk, X509V3_EXT_METHOD* ptr);
X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_pop (stack_st_X509V3_EXT_METHOD* sk);
X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_shift (stack_st_X509V3_EXT_METHOD* sk);
void sk_X509V3_EXT_METHOD_pop_free (stack_st_X509V3_EXT_METHOD* sk, sk_X509V3_EXT_METHOD_freefunc freefunc);
int sk_X509V3_EXT_METHOD_insert (stack_st_X509V3_EXT_METHOD* sk, X509V3_EXT_METHOD* ptr, int idx);
X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_set (stack_st_X509V3_EXT_METHOD* sk, int idx, X509V3_EXT_METHOD* ptr);
int sk_X509V3_EXT_METHOD_find (stack_st_X509V3_EXT_METHOD* sk, X509V3_EXT_METHOD* ptr);
int sk_X509V3_EXT_METHOD_find_ex (stack_st_X509V3_EXT_METHOD* sk, X509V3_EXT_METHOD* ptr);
void sk_X509V3_EXT_METHOD_sort (stack_st_X509V3_EXT_METHOD* sk);
int sk_X509V3_EXT_METHOD_is_sorted (const(stack_st_X509V3_EXT_METHOD)* sk);
stack_st_X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_dup (const(stack_st_X509V3_EXT_METHOD)* sk);
stack_st_X509V3_EXT_METHOD* sk_X509V3_EXT_METHOD_deep_copy (const(stack_st_X509V3_EXT_METHOD)* sk, sk_X509V3_EXT_METHOD_copyfunc copyfunc, sk_X509V3_EXT_METHOD_freefunc freefunc);
sk_X509V3_EXT_METHOD_compfunc sk_X509V3_EXT_METHOD_set_cmp_func (stack_st_X509V3_EXT_METHOD* sk, sk_X509V3_EXT_METHOD_compfunc compare);

/* ext_flags values */
enum X509V3_EXT_DYNAMIC = 0x1;
enum X509V3_EXT_CTX_DEP = 0x2;
enum X509V3_EXT_MULTILINE = 0x4;

alias ENUMERATED_NAMES = BIT_STRING_BITNAME_st;

struct BASIC_CONSTRAINTS_st
{
    int ca;
    ASN1_INTEGER* pathlen;
}

alias BASIC_CONSTRAINTS = BASIC_CONSTRAINTS_st;

struct PKEY_USAGE_PERIOD_st
{
    ASN1_GENERALIZEDTIME* notBefore;
    ASN1_GENERALIZEDTIME* notAfter;
}

alias PKEY_USAGE_PERIOD = PKEY_USAGE_PERIOD_st;

struct otherName_st
{
    ASN1_OBJECT* type_id;
    ASN1_TYPE* value;
}

alias OTHERNAME = otherName_st;

struct EDIPartyName_st
{
    ASN1_STRING* nameAssigner;
    ASN1_STRING* partyName;
}

alias EDIPARTYNAME = EDIPartyName_st;

struct GENERAL_NAME_st
{
    int type;

    /* otherName */

    /* Old names */
    /* iPAddress */
    /* dirn */
    /* rfc822Name, dNSName,
     * uniformResourceIdentifier */
    /* registeredID */
    /* x400Address */
    union _Anonymous_0
    {
        char* ptr;
        OTHERNAME* otherName;
        ASN1_IA5STRING* rfc822Name;
        ASN1_IA5STRING* dNSName;
        ASN1_TYPE* x400Address;
        X509_NAME* directoryName;
        EDIPARTYNAME* ediPartyName;
        ASN1_IA5STRING* uniformResourceIdentifier;
        ASN1_OCTET_STRING* iPAddress;
        ASN1_OBJECT* registeredID;
        ASN1_OCTET_STRING* ip;
        X509_NAME* dirn;
        ASN1_IA5STRING* ia5;
        ASN1_OBJECT* rid;
        ASN1_TYPE* other;
    }

    _Anonymous_0 d;
}

enum GEN_OTHERNAME = 0;
enum GEN_EMAIL = 1;
enum GEN_DNS = 2;
enum GEN_X400 = 3;
enum GEN_DIRNAME = 4;
enum GEN_EDIPARTY = 5;
enum GEN_URI = 6;
enum GEN_IPADD = 7;
enum GEN_RID = 8;
alias GENERAL_NAME = GENERAL_NAME_st;

struct ACCESS_DESCRIPTION_st
{
    ASN1_OBJECT* method;
    GENERAL_NAME* location;
}

alias ACCESS_DESCRIPTION = ACCESS_DESCRIPTION_st;

struct stack_st_ACCESS_DESCRIPTION;
alias AUTHORITY_INFO_ACCESS = stack_st_ACCESS_DESCRIPTION;

/* If relativename then this contains the full distribution point name */

/* All existing reasons */

/* Strong extranet structures */

/* Proxy certificate structures, see RFC 3820 */

/* Values in idp_flags field */
/* IDP present */

/* IDP values inconsistent */

/* onlyuser true */

/* onlyCA true */

/* onlyattr true */

/* indirectCRL true */

/* onlysomereasons present */

/* X509_PURPOSE stuff */

/* Really self issued not necessarily self signed */

/* EXFLAG_SET is set to indicate that some values have been precomputed */

/* Self signed */

/* Default trust ID */

/* Flags for X509V3_EXT_print() */

/* Return error for unknown extensions */

/* Print error for unknown extensions */

/* ASN1 parse unknown extensions */

/* BIO_dump unknown extensions */

/* Flags for X509V3_add1_i2d */

struct stack_st_ASN1_OBJECT;
alias EXTENDED_KEY_USAGE = stack_st_ASN1_OBJECT;
struct stack_st_ASN1_INTEGER;
alias TLS_FEATURE = stack_st_ASN1_INTEGER;
struct stack_st_GENERAL_NAME;
alias sk_GENERAL_NAME_compfunc = int function (const(GENERAL_NAME*)* a, const(GENERAL_NAME*)* b);
alias sk_GENERAL_NAME_freefunc = void function (GENERAL_NAME* a);
alias sk_GENERAL_NAME_copyfunc = GENERAL_NAME_st* function (const(GENERAL_NAME)* a);
int sk_GENERAL_NAME_num (const(stack_st_GENERAL_NAME)* sk);
GENERAL_NAME* sk_GENERAL_NAME_value (const(stack_st_GENERAL_NAME)* sk, int idx);
stack_st_GENERAL_NAME* sk_GENERAL_NAME_new (sk_GENERAL_NAME_compfunc compare);
stack_st_GENERAL_NAME* sk_GENERAL_NAME_new_null ();
void sk_GENERAL_NAME_free (stack_st_GENERAL_NAME* sk);
void sk_GENERAL_NAME_zero (stack_st_GENERAL_NAME* sk);
GENERAL_NAME* sk_GENERAL_NAME_delete (stack_st_GENERAL_NAME* sk, int i);
GENERAL_NAME* sk_GENERAL_NAME_delete_ptr (stack_st_GENERAL_NAME* sk, GENERAL_NAME* ptr);
int sk_GENERAL_NAME_push (stack_st_GENERAL_NAME* sk, GENERAL_NAME* ptr);
int sk_GENERAL_NAME_unshift (stack_st_GENERAL_NAME* sk, GENERAL_NAME* ptr);
GENERAL_NAME* sk_GENERAL_NAME_pop (stack_st_GENERAL_NAME* sk);
GENERAL_NAME* sk_GENERAL_NAME_shift (stack_st_GENERAL_NAME* sk);
void sk_GENERAL_NAME_pop_free (stack_st_GENERAL_NAME* sk, sk_GENERAL_NAME_freefunc freefunc);
int sk_GENERAL_NAME_insert (stack_st_GENERAL_NAME* sk, GENERAL_NAME* ptr, int idx);
GENERAL_NAME* sk_GENERAL_NAME_set (stack_st_GENERAL_NAME* sk, int idx, GENERAL_NAME* ptr);
int sk_GENERAL_NAME_find (stack_st_GENERAL_NAME* sk, GENERAL_NAME* ptr);
int sk_GENERAL_NAME_find_ex (stack_st_GENERAL_NAME* sk, GENERAL_NAME* ptr);
void sk_GENERAL_NAME_sort (stack_st_GENERAL_NAME* sk);
int sk_GENERAL_NAME_is_sorted (const(stack_st_GENERAL_NAME)* sk);
stack_st_GENERAL_NAME* sk_GENERAL_NAME_dup (const(stack_st_GENERAL_NAME)* sk);
stack_st_GENERAL_NAME* sk_GENERAL_NAME_deep_copy (const(stack_st_GENERAL_NAME)* sk, sk_GENERAL_NAME_copyfunc copyfunc, sk_GENERAL_NAME_freefunc freefunc);
sk_GENERAL_NAME_compfunc sk_GENERAL_NAME_set_cmp_func (stack_st_GENERAL_NAME* sk, sk_GENERAL_NAME_compfunc compare);
alias GENERAL_NAMES = stack_st_GENERAL_NAME;
struct stack_st_GENERAL_NAMES;
alias sk_GENERAL_NAMES_compfunc = int function (const(GENERAL_NAMES*)* a, const(GENERAL_NAMES*)* b);
alias sk_GENERAL_NAMES_freefunc = void function (GENERAL_NAMES* a);
alias sk_GENERAL_NAMES_copyfunc = stack_st_GENERAL_NAME* function (const(GENERAL_NAMES)* a);
int sk_GENERAL_NAMES_num (const(stack_st_GENERAL_NAMES)* sk);
GENERAL_NAMES* sk_GENERAL_NAMES_value (const(stack_st_GENERAL_NAMES)* sk, int idx);
stack_st_GENERAL_NAMES* sk_GENERAL_NAMES_new (sk_GENERAL_NAMES_compfunc compare);
stack_st_GENERAL_NAMES* sk_GENERAL_NAMES_new_null ();
void sk_GENERAL_NAMES_free (stack_st_GENERAL_NAMES* sk);
void sk_GENERAL_NAMES_zero (stack_st_GENERAL_NAMES* sk);
GENERAL_NAMES* sk_GENERAL_NAMES_delete (stack_st_GENERAL_NAMES* sk, int i);
GENERAL_NAMES* sk_GENERAL_NAMES_delete_ptr (stack_st_GENERAL_NAMES* sk, GENERAL_NAMES* ptr);
int sk_GENERAL_NAMES_push (stack_st_GENERAL_NAMES* sk, GENERAL_NAMES* ptr);
int sk_GENERAL_NAMES_unshift (stack_st_GENERAL_NAMES* sk, GENERAL_NAMES* ptr);
GENERAL_NAMES* sk_GENERAL_NAMES_pop (stack_st_GENERAL_NAMES* sk);
GENERAL_NAMES* sk_GENERAL_NAMES_shift (stack_st_GENERAL_NAMES* sk);
void sk_GENERAL_NAMES_pop_free (stack_st_GENERAL_NAMES* sk, sk_GENERAL_NAMES_freefunc freefunc);
int sk_GENERAL_NAMES_insert (stack_st_GENERAL_NAMES* sk, GENERAL_NAMES* ptr, int idx);
GENERAL_NAMES* sk_GENERAL_NAMES_set (stack_st_GENERAL_NAMES* sk, int idx, GENERAL_NAMES* ptr);
int sk_GENERAL_NAMES_find (stack_st_GENERAL_NAMES* sk, GENERAL_NAMES* ptr);
int sk_GENERAL_NAMES_find_ex (stack_st_GENERAL_NAMES* sk, GENERAL_NAMES* ptr);
void sk_GENERAL_NAMES_sort (stack_st_GENERAL_NAMES* sk);
int sk_GENERAL_NAMES_is_sorted (const(stack_st_GENERAL_NAMES)* sk);
stack_st_GENERAL_NAMES* sk_GENERAL_NAMES_dup (const(stack_st_GENERAL_NAMES)* sk);
stack_st_GENERAL_NAMES* sk_GENERAL_NAMES_deep_copy (const(stack_st_GENERAL_NAMES)* sk, sk_GENERAL_NAMES_copyfunc copyfunc, sk_GENERAL_NAMES_freefunc freefunc);
sk_GENERAL_NAMES_compfunc sk_GENERAL_NAMES_set_cmp_func (stack_st_GENERAL_NAMES* sk, sk_GENERAL_NAMES_compfunc compare);
alias sk_ACCESS_DESCRIPTION_compfunc = int function (const(ACCESS_DESCRIPTION*)* a, const(ACCESS_DESCRIPTION*)* b);
alias sk_ACCESS_DESCRIPTION_freefunc = void function (ACCESS_DESCRIPTION* a);
alias sk_ACCESS_DESCRIPTION_copyfunc = ACCESS_DESCRIPTION_st* function (const(ACCESS_DESCRIPTION)* a);
int sk_ACCESS_DESCRIPTION_num (const(stack_st_ACCESS_DESCRIPTION)* sk);
ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_value (const(stack_st_ACCESS_DESCRIPTION)* sk, int idx);
stack_st_ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_new (sk_ACCESS_DESCRIPTION_compfunc compare);
stack_st_ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_new_null ();
void sk_ACCESS_DESCRIPTION_free (stack_st_ACCESS_DESCRIPTION* sk);
void sk_ACCESS_DESCRIPTION_zero (stack_st_ACCESS_DESCRIPTION* sk);
ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_delete (stack_st_ACCESS_DESCRIPTION* sk, int i);
ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_delete_ptr (stack_st_ACCESS_DESCRIPTION* sk, ACCESS_DESCRIPTION* ptr);
int sk_ACCESS_DESCRIPTION_push (stack_st_ACCESS_DESCRIPTION* sk, ACCESS_DESCRIPTION* ptr);
int sk_ACCESS_DESCRIPTION_unshift (stack_st_ACCESS_DESCRIPTION* sk, ACCESS_DESCRIPTION* ptr);
ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_pop (stack_st_ACCESS_DESCRIPTION* sk);
ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_shift (stack_st_ACCESS_DESCRIPTION* sk);
void sk_ACCESS_DESCRIPTION_pop_free (stack_st_ACCESS_DESCRIPTION* sk, sk_ACCESS_DESCRIPTION_freefunc freefunc);
int sk_ACCESS_DESCRIPTION_insert (stack_st_ACCESS_DESCRIPTION* sk, ACCESS_DESCRIPTION* ptr, int idx);
ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_set (stack_st_ACCESS_DESCRIPTION* sk, int idx, ACCESS_DESCRIPTION* ptr);
int sk_ACCESS_DESCRIPTION_find (stack_st_ACCESS_DESCRIPTION* sk, ACCESS_DESCRIPTION* ptr);
int sk_ACCESS_DESCRIPTION_find_ex (stack_st_ACCESS_DESCRIPTION* sk, ACCESS_DESCRIPTION* ptr);
void sk_ACCESS_DESCRIPTION_sort (stack_st_ACCESS_DESCRIPTION* sk);
int sk_ACCESS_DESCRIPTION_is_sorted (const(stack_st_ACCESS_DESCRIPTION)* sk);
stack_st_ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_dup (const(stack_st_ACCESS_DESCRIPTION)* sk);
stack_st_ACCESS_DESCRIPTION* sk_ACCESS_DESCRIPTION_deep_copy (const(stack_st_ACCESS_DESCRIPTION)* sk, sk_ACCESS_DESCRIPTION_copyfunc copyfunc, sk_ACCESS_DESCRIPTION_freefunc freefunc);
sk_ACCESS_DESCRIPTION_compfunc sk_ACCESS_DESCRIPTION_set_cmp_func (stack_st_ACCESS_DESCRIPTION* sk, sk_ACCESS_DESCRIPTION_compfunc compare);

struct DIST_POINT_NAME_st
{
    int type;

    union _Anonymous_1
    {
        GENERAL_NAMES* fullname;
        stack_st_X509_NAME_ENTRY* relativename;
    }

    _Anonymous_1 name;
    X509_NAME* dpname;
}

alias DIST_POINT_NAME = DIST_POINT_NAME_st;
enum CRLDP_ALL_REASONS = 0x807f;
enum CRL_REASON_NONE = -1;
enum CRL_REASON_UNSPECIFIED = 0;
enum CRL_REASON_KEY_COMPROMISE = 1;
enum CRL_REASON_CA_COMPROMISE = 2;
enum CRL_REASON_AFFILIATION_CHANGED = 3;
enum CRL_REASON_SUPERSEDED = 4;
enum CRL_REASON_CESSATION_OF_OPERATION = 5;
enum CRL_REASON_CERTIFICATE_HOLD = 6;
enum CRL_REASON_REMOVE_FROM_CRL = 8;
enum CRL_REASON_PRIVILEGE_WITHDRAWN = 9;
enum CRL_REASON_AA_COMPROMISE = 10;

struct DIST_POINT_st
{
    DIST_POINT_NAME* distpoint;
    ASN1_BIT_STRING* reasons;
    GENERAL_NAMES* CRLissuer;
    int dp_reasons;
}

struct stack_st_DIST_POINT;
alias CRL_DIST_POINTS = stack_st_DIST_POINT;
alias sk_DIST_POINT_compfunc = int function (const(DIST_POINT*)* a, const(DIST_POINT*)* b);
alias sk_DIST_POINT_freefunc = void function (DIST_POINT* a);
alias sk_DIST_POINT_copyfunc = DIST_POINT_st* function (const(DIST_POINT)* a);
int sk_DIST_POINT_num (const(stack_st_DIST_POINT)* sk);
DIST_POINT* sk_DIST_POINT_value (const(stack_st_DIST_POINT)* sk, int idx);
stack_st_DIST_POINT* sk_DIST_POINT_new (sk_DIST_POINT_compfunc compare);
stack_st_DIST_POINT* sk_DIST_POINT_new_null ();
void sk_DIST_POINT_free (stack_st_DIST_POINT* sk);
void sk_DIST_POINT_zero (stack_st_DIST_POINT* sk);
DIST_POINT* sk_DIST_POINT_delete (stack_st_DIST_POINT* sk, int i);
DIST_POINT* sk_DIST_POINT_delete_ptr (stack_st_DIST_POINT* sk, DIST_POINT* ptr);
int sk_DIST_POINT_push (stack_st_DIST_POINT* sk, DIST_POINT* ptr);
int sk_DIST_POINT_unshift (stack_st_DIST_POINT* sk, DIST_POINT* ptr);
DIST_POINT* sk_DIST_POINT_pop (stack_st_DIST_POINT* sk);
DIST_POINT* sk_DIST_POINT_shift (stack_st_DIST_POINT* sk);
void sk_DIST_POINT_pop_free (stack_st_DIST_POINT* sk, sk_DIST_POINT_freefunc freefunc);
int sk_DIST_POINT_insert (stack_st_DIST_POINT* sk, DIST_POINT* ptr, int idx);
DIST_POINT* sk_DIST_POINT_set (stack_st_DIST_POINT* sk, int idx, DIST_POINT* ptr);
int sk_DIST_POINT_find (stack_st_DIST_POINT* sk, DIST_POINT* ptr);
int sk_DIST_POINT_find_ex (stack_st_DIST_POINT* sk, DIST_POINT* ptr);
void sk_DIST_POINT_sort (stack_st_DIST_POINT* sk);
int sk_DIST_POINT_is_sorted (const(stack_st_DIST_POINT)* sk);
stack_st_DIST_POINT* sk_DIST_POINT_dup (const(stack_st_DIST_POINT)* sk);
stack_st_DIST_POINT* sk_DIST_POINT_deep_copy (const(stack_st_DIST_POINT)* sk, sk_DIST_POINT_copyfunc copyfunc, sk_DIST_POINT_freefunc freefunc);
sk_DIST_POINT_compfunc sk_DIST_POINT_set_cmp_func (stack_st_DIST_POINT* sk, sk_DIST_POINT_compfunc compare);

struct AUTHORITY_KEYID_st
{
    ASN1_OCTET_STRING* keyid;
    GENERAL_NAMES* issuer;
    ASN1_INTEGER* serial;
}

struct SXNET_ID_st
{
    ASN1_INTEGER* zone;
    ASN1_OCTET_STRING* user;
}

alias SXNETID = SXNET_ID_st;
struct stack_st_SXNETID;
alias sk_SXNETID_compfunc = int function (const(SXNETID*)* a, const(SXNETID*)* b);
alias sk_SXNETID_freefunc = void function (SXNETID* a);
alias sk_SXNETID_copyfunc = SXNET_ID_st* function (const(SXNETID)* a);
int sk_SXNETID_num (const(stack_st_SXNETID)* sk);
SXNETID* sk_SXNETID_value (const(stack_st_SXNETID)* sk, int idx);
stack_st_SXNETID* sk_SXNETID_new (sk_SXNETID_compfunc compare);
stack_st_SXNETID* sk_SXNETID_new_null ();
void sk_SXNETID_free (stack_st_SXNETID* sk);
void sk_SXNETID_zero (stack_st_SXNETID* sk);
SXNETID* sk_SXNETID_delete (stack_st_SXNETID* sk, int i);
SXNETID* sk_SXNETID_delete_ptr (stack_st_SXNETID* sk, SXNETID* ptr);
int sk_SXNETID_push (stack_st_SXNETID* sk, SXNETID* ptr);
int sk_SXNETID_unshift (stack_st_SXNETID* sk, SXNETID* ptr);
SXNETID* sk_SXNETID_pop (stack_st_SXNETID* sk);
SXNETID* sk_SXNETID_shift (stack_st_SXNETID* sk);
void sk_SXNETID_pop_free (stack_st_SXNETID* sk, sk_SXNETID_freefunc freefunc);
int sk_SXNETID_insert (stack_st_SXNETID* sk, SXNETID* ptr, int idx);
SXNETID* sk_SXNETID_set (stack_st_SXNETID* sk, int idx, SXNETID* ptr);
int sk_SXNETID_find (stack_st_SXNETID* sk, SXNETID* ptr);
int sk_SXNETID_find_ex (stack_st_SXNETID* sk, SXNETID* ptr);
void sk_SXNETID_sort (stack_st_SXNETID* sk);
int sk_SXNETID_is_sorted (const(stack_st_SXNETID)* sk);
stack_st_SXNETID* sk_SXNETID_dup (const(stack_st_SXNETID)* sk);
stack_st_SXNETID* sk_SXNETID_deep_copy (const(stack_st_SXNETID)* sk, sk_SXNETID_copyfunc copyfunc, sk_SXNETID_freefunc freefunc);
sk_SXNETID_compfunc sk_SXNETID_set_cmp_func (stack_st_SXNETID* sk, sk_SXNETID_compfunc compare);

struct SXNET_st
{
    ASN1_INTEGER* version_;
    stack_st_SXNETID* ids;
}

alias SXNET = SXNET_st;

struct NOTICEREF_st
{
    ASN1_STRING* organization;
    stack_st_ASN1_INTEGER* noticenos;
}

alias NOTICEREF = NOTICEREF_st;

struct USERNOTICE_st
{
    NOTICEREF* noticeref;
    ASN1_STRING* exptext;
}

alias USERNOTICE = USERNOTICE_st;

struct POLICYQUALINFO_st
{
    ASN1_OBJECT* pqualid;

    union _Anonymous_2
    {
        ASN1_IA5STRING* cpsuri;
        USERNOTICE* usernotice;
        ASN1_TYPE* other;
    }

    _Anonymous_2 d;
}

alias POLICYQUALINFO = POLICYQUALINFO_st;
struct stack_st_POLICYQUALINFO;
alias sk_POLICYQUALINFO_compfunc = int function (const(POLICYQUALINFO*)* a, const(POLICYQUALINFO*)* b);
alias sk_POLICYQUALINFO_freefunc = void function (POLICYQUALINFO* a);
alias sk_POLICYQUALINFO_copyfunc = POLICYQUALINFO_st* function (const(POLICYQUALINFO)* a);
int sk_POLICYQUALINFO_num (const(stack_st_POLICYQUALINFO)* sk);
POLICYQUALINFO* sk_POLICYQUALINFO_value (const(stack_st_POLICYQUALINFO)* sk, int idx);
stack_st_POLICYQUALINFO* sk_POLICYQUALINFO_new (sk_POLICYQUALINFO_compfunc compare);
stack_st_POLICYQUALINFO* sk_POLICYQUALINFO_new_null ();
void sk_POLICYQUALINFO_free (stack_st_POLICYQUALINFO* sk);
void sk_POLICYQUALINFO_zero (stack_st_POLICYQUALINFO* sk);
POLICYQUALINFO* sk_POLICYQUALINFO_delete (stack_st_POLICYQUALINFO* sk, int i);
POLICYQUALINFO* sk_POLICYQUALINFO_delete_ptr (stack_st_POLICYQUALINFO* sk, POLICYQUALINFO* ptr);
int sk_POLICYQUALINFO_push (stack_st_POLICYQUALINFO* sk, POLICYQUALINFO* ptr);
int sk_POLICYQUALINFO_unshift (stack_st_POLICYQUALINFO* sk, POLICYQUALINFO* ptr);
POLICYQUALINFO* sk_POLICYQUALINFO_pop (stack_st_POLICYQUALINFO* sk);
POLICYQUALINFO* sk_POLICYQUALINFO_shift (stack_st_POLICYQUALINFO* sk);
void sk_POLICYQUALINFO_pop_free (stack_st_POLICYQUALINFO* sk, sk_POLICYQUALINFO_freefunc freefunc);
int sk_POLICYQUALINFO_insert (stack_st_POLICYQUALINFO* sk, POLICYQUALINFO* ptr, int idx);
POLICYQUALINFO* sk_POLICYQUALINFO_set (stack_st_POLICYQUALINFO* sk, int idx, POLICYQUALINFO* ptr);
int sk_POLICYQUALINFO_find (stack_st_POLICYQUALINFO* sk, POLICYQUALINFO* ptr);
int sk_POLICYQUALINFO_find_ex (stack_st_POLICYQUALINFO* sk, POLICYQUALINFO* ptr);
void sk_POLICYQUALINFO_sort (stack_st_POLICYQUALINFO* sk);
int sk_POLICYQUALINFO_is_sorted (const(stack_st_POLICYQUALINFO)* sk);
stack_st_POLICYQUALINFO* sk_POLICYQUALINFO_dup (const(stack_st_POLICYQUALINFO)* sk);
stack_st_POLICYQUALINFO* sk_POLICYQUALINFO_deep_copy (const(stack_st_POLICYQUALINFO)* sk, sk_POLICYQUALINFO_copyfunc copyfunc, sk_POLICYQUALINFO_freefunc freefunc);
sk_POLICYQUALINFO_compfunc sk_POLICYQUALINFO_set_cmp_func (stack_st_POLICYQUALINFO* sk, sk_POLICYQUALINFO_compfunc compare);

struct POLICYINFO_st
{
    ASN1_OBJECT* policyid;
    stack_st_POLICYQUALINFO* qualifiers;
}

alias POLICYINFO = POLICYINFO_st;
struct stack_st_POLICYINFO;
alias CERTIFICATEPOLICIES = stack_st_POLICYINFO;
alias sk_POLICYINFO_compfunc = int function (const(POLICYINFO*)* a, const(POLICYINFO*)* b);
alias sk_POLICYINFO_freefunc = void function (POLICYINFO* a);
alias sk_POLICYINFO_copyfunc = POLICYINFO_st* function (const(POLICYINFO)* a);
int sk_POLICYINFO_num (const(stack_st_POLICYINFO)* sk);
POLICYINFO* sk_POLICYINFO_value (const(stack_st_POLICYINFO)* sk, int idx);
stack_st_POLICYINFO* sk_POLICYINFO_new (sk_POLICYINFO_compfunc compare);
stack_st_POLICYINFO* sk_POLICYINFO_new_null ();
void sk_POLICYINFO_free (stack_st_POLICYINFO* sk);
void sk_POLICYINFO_zero (stack_st_POLICYINFO* sk);
POLICYINFO* sk_POLICYINFO_delete (stack_st_POLICYINFO* sk, int i);
POLICYINFO* sk_POLICYINFO_delete_ptr (stack_st_POLICYINFO* sk, POLICYINFO* ptr);
int sk_POLICYINFO_push (stack_st_POLICYINFO* sk, POLICYINFO* ptr);
int sk_POLICYINFO_unshift (stack_st_POLICYINFO* sk, POLICYINFO* ptr);
POLICYINFO* sk_POLICYINFO_pop (stack_st_POLICYINFO* sk);
POLICYINFO* sk_POLICYINFO_shift (stack_st_POLICYINFO* sk);
void sk_POLICYINFO_pop_free (stack_st_POLICYINFO* sk, sk_POLICYINFO_freefunc freefunc);
int sk_POLICYINFO_insert (stack_st_POLICYINFO* sk, POLICYINFO* ptr, int idx);
POLICYINFO* sk_POLICYINFO_set (stack_st_POLICYINFO* sk, int idx, POLICYINFO* ptr);
int sk_POLICYINFO_find (stack_st_POLICYINFO* sk, POLICYINFO* ptr);
int sk_POLICYINFO_find_ex (stack_st_POLICYINFO* sk, POLICYINFO* ptr);
void sk_POLICYINFO_sort (stack_st_POLICYINFO* sk);
int sk_POLICYINFO_is_sorted (const(stack_st_POLICYINFO)* sk);
stack_st_POLICYINFO* sk_POLICYINFO_dup (const(stack_st_POLICYINFO)* sk);
stack_st_POLICYINFO* sk_POLICYINFO_deep_copy (const(stack_st_POLICYINFO)* sk, sk_POLICYINFO_copyfunc copyfunc, sk_POLICYINFO_freefunc freefunc);
sk_POLICYINFO_compfunc sk_POLICYINFO_set_cmp_func (stack_st_POLICYINFO* sk, sk_POLICYINFO_compfunc compare);

struct POLICY_MAPPING_st
{
    ASN1_OBJECT* issuerDomainPolicy;
    ASN1_OBJECT* subjectDomainPolicy;
}

alias POLICY_MAPPING = POLICY_MAPPING_st;
struct stack_st_POLICY_MAPPING;
alias sk_POLICY_MAPPING_compfunc = int function (const(POLICY_MAPPING*)* a, const(POLICY_MAPPING*)* b);
alias sk_POLICY_MAPPING_freefunc = void function (POLICY_MAPPING* a);
alias sk_POLICY_MAPPING_copyfunc = POLICY_MAPPING_st* function (const(POLICY_MAPPING)* a);
int sk_POLICY_MAPPING_num (const(stack_st_POLICY_MAPPING)* sk);
POLICY_MAPPING* sk_POLICY_MAPPING_value (const(stack_st_POLICY_MAPPING)* sk, int idx);
stack_st_POLICY_MAPPING* sk_POLICY_MAPPING_new (sk_POLICY_MAPPING_compfunc compare);
stack_st_POLICY_MAPPING* sk_POLICY_MAPPING_new_null ();
void sk_POLICY_MAPPING_free (stack_st_POLICY_MAPPING* sk);
void sk_POLICY_MAPPING_zero (stack_st_POLICY_MAPPING* sk);
POLICY_MAPPING* sk_POLICY_MAPPING_delete (stack_st_POLICY_MAPPING* sk, int i);
POLICY_MAPPING* sk_POLICY_MAPPING_delete_ptr (stack_st_POLICY_MAPPING* sk, POLICY_MAPPING* ptr);
int sk_POLICY_MAPPING_push (stack_st_POLICY_MAPPING* sk, POLICY_MAPPING* ptr);
int sk_POLICY_MAPPING_unshift (stack_st_POLICY_MAPPING* sk, POLICY_MAPPING* ptr);
POLICY_MAPPING* sk_POLICY_MAPPING_pop (stack_st_POLICY_MAPPING* sk);
POLICY_MAPPING* sk_POLICY_MAPPING_shift (stack_st_POLICY_MAPPING* sk);
void sk_POLICY_MAPPING_pop_free (stack_st_POLICY_MAPPING* sk, sk_POLICY_MAPPING_freefunc freefunc);
int sk_POLICY_MAPPING_insert (stack_st_POLICY_MAPPING* sk, POLICY_MAPPING* ptr, int idx);
POLICY_MAPPING* sk_POLICY_MAPPING_set (stack_st_POLICY_MAPPING* sk, int idx, POLICY_MAPPING* ptr);
int sk_POLICY_MAPPING_find (stack_st_POLICY_MAPPING* sk, POLICY_MAPPING* ptr);
int sk_POLICY_MAPPING_find_ex (stack_st_POLICY_MAPPING* sk, POLICY_MAPPING* ptr);
void sk_POLICY_MAPPING_sort (stack_st_POLICY_MAPPING* sk);
int sk_POLICY_MAPPING_is_sorted (const(stack_st_POLICY_MAPPING)* sk);
stack_st_POLICY_MAPPING* sk_POLICY_MAPPING_dup (const(stack_st_POLICY_MAPPING)* sk);
stack_st_POLICY_MAPPING* sk_POLICY_MAPPING_deep_copy (const(stack_st_POLICY_MAPPING)* sk, sk_POLICY_MAPPING_copyfunc copyfunc, sk_POLICY_MAPPING_freefunc freefunc);
sk_POLICY_MAPPING_compfunc sk_POLICY_MAPPING_set_cmp_func (stack_st_POLICY_MAPPING* sk, sk_POLICY_MAPPING_compfunc compare);
alias POLICY_MAPPINGS = stack_st_POLICY_MAPPING;

struct GENERAL_SUBTREE_st
{
    GENERAL_NAME* base;
    ASN1_INTEGER* minimum;
    ASN1_INTEGER* maximum;
}

alias GENERAL_SUBTREE = GENERAL_SUBTREE_st;
struct stack_st_GENERAL_SUBTREE;
alias sk_GENERAL_SUBTREE_compfunc = int function (const(GENERAL_SUBTREE*)* a, const(GENERAL_SUBTREE*)* b);
alias sk_GENERAL_SUBTREE_freefunc = void function (GENERAL_SUBTREE* a);
alias sk_GENERAL_SUBTREE_copyfunc = GENERAL_SUBTREE_st* function (const(GENERAL_SUBTREE)* a);
int sk_GENERAL_SUBTREE_num (const(stack_st_GENERAL_SUBTREE)* sk);
GENERAL_SUBTREE* sk_GENERAL_SUBTREE_value (const(stack_st_GENERAL_SUBTREE)* sk, int idx);
stack_st_GENERAL_SUBTREE* sk_GENERAL_SUBTREE_new (sk_GENERAL_SUBTREE_compfunc compare);
stack_st_GENERAL_SUBTREE* sk_GENERAL_SUBTREE_new_null ();
void sk_GENERAL_SUBTREE_free (stack_st_GENERAL_SUBTREE* sk);
void sk_GENERAL_SUBTREE_zero (stack_st_GENERAL_SUBTREE* sk);
GENERAL_SUBTREE* sk_GENERAL_SUBTREE_delete (stack_st_GENERAL_SUBTREE* sk, int i);
GENERAL_SUBTREE* sk_GENERAL_SUBTREE_delete_ptr (stack_st_GENERAL_SUBTREE* sk, GENERAL_SUBTREE* ptr);
int sk_GENERAL_SUBTREE_push (stack_st_GENERAL_SUBTREE* sk, GENERAL_SUBTREE* ptr);
int sk_GENERAL_SUBTREE_unshift (stack_st_GENERAL_SUBTREE* sk, GENERAL_SUBTREE* ptr);
GENERAL_SUBTREE* sk_GENERAL_SUBTREE_pop (stack_st_GENERAL_SUBTREE* sk);
GENERAL_SUBTREE* sk_GENERAL_SUBTREE_shift (stack_st_GENERAL_SUBTREE* sk);
void sk_GENERAL_SUBTREE_pop_free (stack_st_GENERAL_SUBTREE* sk, sk_GENERAL_SUBTREE_freefunc freefunc);
int sk_GENERAL_SUBTREE_insert (stack_st_GENERAL_SUBTREE* sk, GENERAL_SUBTREE* ptr, int idx);
GENERAL_SUBTREE* sk_GENERAL_SUBTREE_set (stack_st_GENERAL_SUBTREE* sk, int idx, GENERAL_SUBTREE* ptr);
int sk_GENERAL_SUBTREE_find (stack_st_GENERAL_SUBTREE* sk, GENERAL_SUBTREE* ptr);
int sk_GENERAL_SUBTREE_find_ex (stack_st_GENERAL_SUBTREE* sk, GENERAL_SUBTREE* ptr);
void sk_GENERAL_SUBTREE_sort (stack_st_GENERAL_SUBTREE* sk);
int sk_GENERAL_SUBTREE_is_sorted (const(stack_st_GENERAL_SUBTREE)* sk);
stack_st_GENERAL_SUBTREE* sk_GENERAL_SUBTREE_dup (const(stack_st_GENERAL_SUBTREE)* sk);
stack_st_GENERAL_SUBTREE* sk_GENERAL_SUBTREE_deep_copy (const(stack_st_GENERAL_SUBTREE)* sk, sk_GENERAL_SUBTREE_copyfunc copyfunc, sk_GENERAL_SUBTREE_freefunc freefunc);
sk_GENERAL_SUBTREE_compfunc sk_GENERAL_SUBTREE_set_cmp_func (stack_st_GENERAL_SUBTREE* sk, sk_GENERAL_SUBTREE_compfunc compare);

struct NAME_CONSTRAINTS_st
{
    stack_st_GENERAL_SUBTREE* permittedSubtrees;
    stack_st_GENERAL_SUBTREE* excludedSubtrees;
}

struct POLICY_CONSTRAINTS_st
{
    ASN1_INTEGER* requireExplicitPolicy;
    ASN1_INTEGER* inhibitPolicyMapping;
}

alias POLICY_CONSTRAINTS = POLICY_CONSTRAINTS_st;

struct PROXY_POLICY_st
{
    ASN1_OBJECT* policyLanguage;
    ASN1_OCTET_STRING* policy;
}

alias PROXY_POLICY = PROXY_POLICY_st;

struct PROXY_CERT_INFO_EXTENSION_st
{
    ASN1_INTEGER* pcPathLengthConstraint;
    PROXY_POLICY* proxyPolicy;
}

alias PROXY_CERT_INFO_EXTENSION = PROXY_CERT_INFO_EXTENSION_st;
PROXY_POLICY* PROXY_POLICY_new ();
void PROXY_POLICY_free (PROXY_POLICY* a);
PROXY_POLICY* d2i_PROXY_POLICY (PROXY_POLICY** a, const(ubyte*)* in_, c_long len);
int i2d_PROXY_POLICY (PROXY_POLICY* a, ubyte** out_);
extern __gshared const ASN1_ITEM PROXY_POLICY_it;
PROXY_CERT_INFO_EXTENSION* PROXY_CERT_INFO_EXTENSION_new ();
void PROXY_CERT_INFO_EXTENSION_free (PROXY_CERT_INFO_EXTENSION* a);
PROXY_CERT_INFO_EXTENSION* d2i_PROXY_CERT_INFO_EXTENSION (PROXY_CERT_INFO_EXTENSION** a, const(ubyte*)* in_, c_long len);
int i2d_PROXY_CERT_INFO_EXTENSION (PROXY_CERT_INFO_EXTENSION* a, ubyte** out_);
extern __gshared const ASN1_ITEM PROXY_CERT_INFO_EXTENSION_it;

struct ISSUING_DIST_POINT_st
{
    DIST_POINT_NAME* distpoint;
    int onlyuser;
    int onlyCA;
    ASN1_BIT_STRING* onlysomereasons;
    int indirectCRL;
    int onlyattr;
}

enum IDP_PRESENT = 0x1;
enum IDP_INVALID = 0x2;
enum IDP_ONLYUSER = 0x4;
enum IDP_ONLYCA = 0x8;
enum IDP_ONLYATTR = 0x10;
enum IDP_INDIRECT = 0x20;
enum IDP_REASONS = 0x40;

extern (D) auto X509V3_set_ctx_test(T)(auto ref T ctx)
{
    return X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, CTX_TEST);
}

enum EXFLAG_BCONS = 0x1;
enum EXFLAG_KUSAGE = 0x2;
enum EXFLAG_XKUSAGE = 0x4;
enum EXFLAG_NSCERT = 0x8;
enum EXFLAG_CA = 0x10;
enum EXFLAG_SI = 0x20;
enum EXFLAG_V1 = 0x40;
enum EXFLAG_INVALID = 0x80;
enum EXFLAG_SET = 0x100;
enum EXFLAG_CRITICAL = 0x200;
enum EXFLAG_PROXY = 0x400;
enum EXFLAG_INVALID_POLICY = 0x800;
enum EXFLAG_FRESHEST = 0x1000;
enum EXFLAG_SS = 0x2000;
enum KU_DIGITAL_SIGNATURE = 0x0080;
enum KU_NON_REPUDIATION = 0x0040;
enum KU_KEY_ENCIPHERMENT = 0x0020;
enum KU_DATA_ENCIPHERMENT = 0x0010;
enum KU_KEY_AGREEMENT = 0x0008;
enum KU_KEY_CERT_SIGN = 0x0004;
enum KU_CRL_SIGN = 0x0002;
enum KU_ENCIPHER_ONLY = 0x0001;
enum KU_DECIPHER_ONLY = 0x8000;
enum NS_SSL_CLIENT = 0x80;
enum NS_SSL_SERVER = 0x40;
enum NS_SMIME = 0x20;
enum NS_OBJSIGN = 0x10;
enum NS_SSL_CA = 0x04;
enum NS_SMIME_CA = 0x02;
enum NS_OBJSIGN_CA = 0x01;
enum NS_ANY_CA = NS_SSL_CA | NS_SMIME_CA | NS_OBJSIGN_CA;
enum XKU_SSL_SERVER = 0x1;
enum XKU_SSL_CLIENT = 0x2;
enum XKU_SMIME = 0x4;
enum XKU_CODE_SIGN = 0x8;
enum XKU_SGC = 0x10;
enum XKU_OCSP_SIGN = 0x20;
enum XKU_TIMESTAMP = 0x40;
enum XKU_DVCS = 0x80;
enum XKU_ANYEKU = 0x100;
enum X509_PURPOSE_DYNAMIC = 0x1;
enum X509_PURPOSE_DYNAMIC_NAME = 0x2;

struct x509_purpose_st
{
    int purpose;
    int trust;
    int flags;
    int function (const(x509_purpose_st)*, const(X509)*, int) check_purpose;
    char* name;
    char* sname;
    void* usr_data;
}

alias X509_PURPOSE = x509_purpose_st;
enum X509_PURPOSE_SSL_CLIENT = 1;
enum X509_PURPOSE_SSL_SERVER = 2;
enum X509_PURPOSE_NS_SSL_SERVER = 3;
enum X509_PURPOSE_SMIME_SIGN = 4;
enum X509_PURPOSE_SMIME_ENCRYPT = 5;
enum X509_PURPOSE_CRL_SIGN = 6;
enum X509_PURPOSE_ANY = 7;
enum X509_PURPOSE_OCSP_HELPER = 8;
enum X509_PURPOSE_TIMESTAMP_SIGN = 9;
enum X509_PURPOSE_MIN = 1;
enum X509_PURPOSE_MAX = 9;
enum X509V3_EXT_UNKNOWN_MASK = 0xfL << 16;
enum X509V3_EXT_DEFAULT = 0;
enum X509V3_EXT_ERROR_UNKNOWN = 1L << 16;
enum X509V3_EXT_PARSE_UNKNOWN = 2L << 16;
enum X509V3_EXT_DUMP_UNKNOWN = 3L << 16;
enum X509V3_ADD_OP_MASK = 0xfL;
enum X509V3_ADD_DEFAULT = 0L;
enum X509V3_ADD_APPEND = 1L;
enum X509V3_ADD_REPLACE = 2L;
enum X509V3_ADD_REPLACE_EXISTING = 3L;
enum X509V3_ADD_KEEP_EXISTING = 4L;
enum X509V3_ADD_DELETE = 5L;
enum X509V3_ADD_SILENT = 0x10;
struct stack_st_X509_PURPOSE;
alias sk_X509_PURPOSE_compfunc = int function (const(X509_PURPOSE*)* a, const(X509_PURPOSE*)* b);
alias sk_X509_PURPOSE_freefunc = void function (X509_PURPOSE* a);
alias sk_X509_PURPOSE_copyfunc = x509_purpose_st* function (const(X509_PURPOSE)* a);
int sk_X509_PURPOSE_num (const(stack_st_X509_PURPOSE)* sk);
X509_PURPOSE* sk_X509_PURPOSE_value (const(stack_st_X509_PURPOSE)* sk, int idx);
stack_st_X509_PURPOSE* sk_X509_PURPOSE_new (sk_X509_PURPOSE_compfunc compare);
stack_st_X509_PURPOSE* sk_X509_PURPOSE_new_null ();
void sk_X509_PURPOSE_free (stack_st_X509_PURPOSE* sk);
void sk_X509_PURPOSE_zero (stack_st_X509_PURPOSE* sk);
X509_PURPOSE* sk_X509_PURPOSE_delete (stack_st_X509_PURPOSE* sk, int i);
X509_PURPOSE* sk_X509_PURPOSE_delete_ptr (stack_st_X509_PURPOSE* sk, X509_PURPOSE* ptr);
int sk_X509_PURPOSE_push (stack_st_X509_PURPOSE* sk, X509_PURPOSE* ptr);
int sk_X509_PURPOSE_unshift (stack_st_X509_PURPOSE* sk, X509_PURPOSE* ptr);
X509_PURPOSE* sk_X509_PURPOSE_pop (stack_st_X509_PURPOSE* sk);
X509_PURPOSE* sk_X509_PURPOSE_shift (stack_st_X509_PURPOSE* sk);
void sk_X509_PURPOSE_pop_free (stack_st_X509_PURPOSE* sk, sk_X509_PURPOSE_freefunc freefunc);
int sk_X509_PURPOSE_insert (stack_st_X509_PURPOSE* sk, X509_PURPOSE* ptr, int idx);
X509_PURPOSE* sk_X509_PURPOSE_set (stack_st_X509_PURPOSE* sk, int idx, X509_PURPOSE* ptr);
int sk_X509_PURPOSE_find (stack_st_X509_PURPOSE* sk, X509_PURPOSE* ptr);
int sk_X509_PURPOSE_find_ex (stack_st_X509_PURPOSE* sk, X509_PURPOSE* ptr);
void sk_X509_PURPOSE_sort (stack_st_X509_PURPOSE* sk);
int sk_X509_PURPOSE_is_sorted (const(stack_st_X509_PURPOSE)* sk);
stack_st_X509_PURPOSE* sk_X509_PURPOSE_dup (const(stack_st_X509_PURPOSE)* sk);
stack_st_X509_PURPOSE* sk_X509_PURPOSE_deep_copy (const(stack_st_X509_PURPOSE)* sk, sk_X509_PURPOSE_copyfunc copyfunc, sk_X509_PURPOSE_freefunc freefunc);
sk_X509_PURPOSE_compfunc sk_X509_PURPOSE_set_cmp_func (stack_st_X509_PURPOSE* sk, sk_X509_PURPOSE_compfunc compare);
BASIC_CONSTRAINTS* BASIC_CONSTRAINTS_new ();
void BASIC_CONSTRAINTS_free (BASIC_CONSTRAINTS* a);
BASIC_CONSTRAINTS* d2i_BASIC_CONSTRAINTS (BASIC_CONSTRAINTS** a, const(ubyte*)* in_, c_long len);
int i2d_BASIC_CONSTRAINTS (BASIC_CONSTRAINTS* a, ubyte** out_);
extern __gshared const ASN1_ITEM BASIC_CONSTRAINTS_it;
SXNET* SXNET_new ();
void SXNET_free (SXNET* a);
SXNET* d2i_SXNET (SXNET** a, const(ubyte*)* in_, c_long len);
int i2d_SXNET (SXNET* a, ubyte** out_);
extern __gshared const ASN1_ITEM SXNET_it;
SXNETID* SXNETID_new ();
void SXNETID_free (SXNETID* a);
SXNETID* d2i_SXNETID (SXNETID** a, const(ubyte*)* in_, c_long len);
int i2d_SXNETID (SXNETID* a, ubyte** out_);
extern __gshared const ASN1_ITEM SXNETID_it;
int SXNET_add_id_asc (SXNET** psx, const(char)* zone, const(char)* user, int userlen);
int SXNET_add_id_ulong (
    SXNET** psx,
    c_ulong lzone,
    const(char)* user,
    int userlen);
int SXNET_add_id_INTEGER (
    SXNET** psx,
    ASN1_INTEGER* izone,
    const(char)* user,
    int userlen);
ASN1_OCTET_STRING* SXNET_get_id_asc (SXNET* sx, const(char)* zone);
ASN1_OCTET_STRING* SXNET_get_id_ulong (SXNET* sx, c_ulong lzone);
ASN1_OCTET_STRING* SXNET_get_id_INTEGER (SXNET* sx, ASN1_INTEGER* zone);
AUTHORITY_KEYID* AUTHORITY_KEYID_new ();
void AUTHORITY_KEYID_free (AUTHORITY_KEYID* a);
AUTHORITY_KEYID* d2i_AUTHORITY_KEYID (AUTHORITY_KEYID** a, const(ubyte*)* in_, c_long len);
int i2d_AUTHORITY_KEYID (AUTHORITY_KEYID* a, ubyte** out_);
extern __gshared const ASN1_ITEM AUTHORITY_KEYID_it;
PKEY_USAGE_PERIOD* PKEY_USAGE_PERIOD_new ();
void PKEY_USAGE_PERIOD_free (PKEY_USAGE_PERIOD* a);
PKEY_USAGE_PERIOD* d2i_PKEY_USAGE_PERIOD (PKEY_USAGE_PERIOD** a, const(ubyte*)* in_, c_long len);
int i2d_PKEY_USAGE_PERIOD (PKEY_USAGE_PERIOD* a, ubyte** out_);
extern __gshared const ASN1_ITEM PKEY_USAGE_PERIOD_it;
GENERAL_NAME* GENERAL_NAME_new ();
void GENERAL_NAME_free (GENERAL_NAME* a);
GENERAL_NAME* d2i_GENERAL_NAME (GENERAL_NAME** a, const(ubyte*)* in_, c_long len);
int i2d_GENERAL_NAME (GENERAL_NAME* a, ubyte** out_);
extern __gshared const ASN1_ITEM GENERAL_NAME_it;
GENERAL_NAME* GENERAL_NAME_dup (GENERAL_NAME* a);
int GENERAL_NAME_cmp (GENERAL_NAME* a, GENERAL_NAME* b);
ASN1_BIT_STRING* v2i_ASN1_BIT_STRING (
    X509V3_EXT_METHOD* method,
    X509V3_CTX* ctx,
    stack_st_CONF_VALUE* nval);
stack_st_CONF_VALUE* i2v_ASN1_BIT_STRING (
    X509V3_EXT_METHOD* method,
    ASN1_BIT_STRING* bits,
    stack_st_CONF_VALUE* extlist);
char* i2s_ASN1_IA5STRING (X509V3_EXT_METHOD* method, ASN1_IA5STRING* ia5);
ASN1_IA5STRING* s2i_ASN1_IA5STRING (
    X509V3_EXT_METHOD* method,
    X509V3_CTX* ctx,
    const(char)* str);
stack_st_CONF_VALUE* i2v_GENERAL_NAME (
    X509V3_EXT_METHOD* method,
    GENERAL_NAME* gen,
    stack_st_CONF_VALUE* ret);
int GENERAL_NAME_print (BIO* out_, GENERAL_NAME* gen);
GENERAL_NAMES* GENERAL_NAMES_new ();
void GENERAL_NAMES_free (GENERAL_NAMES* a);
GENERAL_NAMES* d2i_GENERAL_NAMES (GENERAL_NAMES** a, const(ubyte*)* in_, c_long len);
int i2d_GENERAL_NAMES (GENERAL_NAMES* a, ubyte** out_);
extern __gshared const ASN1_ITEM GENERAL_NAMES_it;
stack_st_CONF_VALUE* i2v_GENERAL_NAMES (
    X509V3_EXT_METHOD* method,
    GENERAL_NAMES* gen,
    stack_st_CONF_VALUE* extlist);
GENERAL_NAMES* v2i_GENERAL_NAMES (
    const(X509V3_EXT_METHOD)* method,
    X509V3_CTX* ctx,
    stack_st_CONF_VALUE* nval);
OTHERNAME* OTHERNAME_new ();
void OTHERNAME_free (OTHERNAME* a);
OTHERNAME* d2i_OTHERNAME (OTHERNAME** a, const(ubyte*)* in_, c_long len);
int i2d_OTHERNAME (OTHERNAME* a, ubyte** out_);
extern __gshared const ASN1_ITEM OTHERNAME_it;
EDIPARTYNAME* EDIPARTYNAME_new ();
void EDIPARTYNAME_free (EDIPARTYNAME* a);
EDIPARTYNAME* d2i_EDIPARTYNAME (EDIPARTYNAME** a, const(ubyte*)* in_, c_long len);
int i2d_EDIPARTYNAME (EDIPARTYNAME* a, ubyte** out_);
extern __gshared const ASN1_ITEM EDIPARTYNAME_it;
int OTHERNAME_cmp (OTHERNAME* a, OTHERNAME* b);
void GENERAL_NAME_set0_value (GENERAL_NAME* a, int type, void* value);
void* GENERAL_NAME_get0_value (GENERAL_NAME* a, int* ptype);
int GENERAL_NAME_set0_othername (
    GENERAL_NAME* gen,
    ASN1_OBJECT* oid,
    ASN1_TYPE* value);
int GENERAL_NAME_get0_otherName (
    GENERAL_NAME* gen,
    ASN1_OBJECT** poid,
    ASN1_TYPE** pvalue);
char* i2s_ASN1_OCTET_STRING (
    X509V3_EXT_METHOD* method,
    const(ASN1_OCTET_STRING)* ia5);
ASN1_OCTET_STRING* s2i_ASN1_OCTET_STRING (
    X509V3_EXT_METHOD* method,
    X509V3_CTX* ctx,
    const(char)* str);
EXTENDED_KEY_USAGE* EXTENDED_KEY_USAGE_new ();
void EXTENDED_KEY_USAGE_free (EXTENDED_KEY_USAGE* a);
EXTENDED_KEY_USAGE* d2i_EXTENDED_KEY_USAGE (EXTENDED_KEY_USAGE** a, const(ubyte*)* in_, c_long len);
int i2d_EXTENDED_KEY_USAGE (EXTENDED_KEY_USAGE* a, ubyte** out_);
extern __gshared const ASN1_ITEM EXTENDED_KEY_USAGE_it;
int i2a_ACCESS_DESCRIPTION (BIO* bp, const(ACCESS_DESCRIPTION)* a);
TLS_FEATURE* TLS_FEATURE_new ();
void TLS_FEATURE_free (TLS_FEATURE* a);
CERTIFICATEPOLICIES* CERTIFICATEPOLICIES_new ();
void CERTIFICATEPOLICIES_free (CERTIFICATEPOLICIES* a);
CERTIFICATEPOLICIES* d2i_CERTIFICATEPOLICIES (CERTIFICATEPOLICIES** a, const(ubyte*)* in_, c_long len);
int i2d_CERTIFICATEPOLICIES (CERTIFICATEPOLICIES* a, ubyte** out_);
extern __gshared const ASN1_ITEM CERTIFICATEPOLICIES_it;
POLICYINFO* POLICYINFO_new ();
void POLICYINFO_free (POLICYINFO* a);
POLICYINFO* d2i_POLICYINFO (POLICYINFO** a, const(ubyte*)* in_, c_long len);
int i2d_POLICYINFO (POLICYINFO* a, ubyte** out_);
extern __gshared const ASN1_ITEM POLICYINFO_it;
POLICYQUALINFO* POLICYQUALINFO_new ();
void POLICYQUALINFO_free (POLICYQUALINFO* a);
POLICYQUALINFO* d2i_POLICYQUALINFO (POLICYQUALINFO** a, const(ubyte*)* in_, c_long len);
int i2d_POLICYQUALINFO (POLICYQUALINFO* a, ubyte** out_);
extern __gshared const ASN1_ITEM POLICYQUALINFO_it;
USERNOTICE* USERNOTICE_new ();
void USERNOTICE_free (USERNOTICE* a);
USERNOTICE* d2i_USERNOTICE (USERNOTICE** a, const(ubyte*)* in_, c_long len);
int i2d_USERNOTICE (USERNOTICE* a, ubyte** out_);
extern __gshared const ASN1_ITEM USERNOTICE_it;
NOTICEREF* NOTICEREF_new ();
void NOTICEREF_free (NOTICEREF* a);
NOTICEREF* d2i_NOTICEREF (NOTICEREF** a, const(ubyte*)* in_, c_long len);
int i2d_NOTICEREF (NOTICEREF* a, ubyte** out_);
extern __gshared const ASN1_ITEM NOTICEREF_it;
CRL_DIST_POINTS* CRL_DIST_POINTS_new ();
void CRL_DIST_POINTS_free (CRL_DIST_POINTS* a);
CRL_DIST_POINTS* d2i_CRL_DIST_POINTS (CRL_DIST_POINTS** a, const(ubyte*)* in_, c_long len);
int i2d_CRL_DIST_POINTS (CRL_DIST_POINTS* a, ubyte** out_);
extern __gshared const ASN1_ITEM CRL_DIST_POINTS_it;
DIST_POINT* DIST_POINT_new ();
void DIST_POINT_free (DIST_POINT* a);
DIST_POINT* d2i_DIST_POINT (DIST_POINT** a, const(ubyte*)* in_, c_long len);
int i2d_DIST_POINT (DIST_POINT* a, ubyte** out_);
extern __gshared const ASN1_ITEM DIST_POINT_it;
DIST_POINT_NAME* DIST_POINT_NAME_new ();
void DIST_POINT_NAME_free (DIST_POINT_NAME* a);
DIST_POINT_NAME* d2i_DIST_POINT_NAME (DIST_POINT_NAME** a, const(ubyte*)* in_, c_long len);
int i2d_DIST_POINT_NAME (DIST_POINT_NAME* a, ubyte** out_);
extern __gshared const ASN1_ITEM DIST_POINT_NAME_it;
ISSUING_DIST_POINT* ISSUING_DIST_POINT_new ();
void ISSUING_DIST_POINT_free (ISSUING_DIST_POINT* a);
ISSUING_DIST_POINT* d2i_ISSUING_DIST_POINT (ISSUING_DIST_POINT** a, const(ubyte*)* in_, c_long len);
int i2d_ISSUING_DIST_POINT (ISSUING_DIST_POINT* a, ubyte** out_);
extern __gshared const ASN1_ITEM ISSUING_DIST_POINT_it;
int DIST_POINT_set_dpname (DIST_POINT_NAME* dpn, X509_NAME* iname);
int NAME_CONSTRAINTS_check (X509* x, NAME_CONSTRAINTS* nc);
int NAME_CONSTRAINTS_check_CN (X509* x, NAME_CONSTRAINTS* nc);
ACCESS_DESCRIPTION* ACCESS_DESCRIPTION_new ();
void ACCESS_DESCRIPTION_free (ACCESS_DESCRIPTION* a);
ACCESS_DESCRIPTION* d2i_ACCESS_DESCRIPTION (ACCESS_DESCRIPTION** a, const(ubyte*)* in_, c_long len);
int i2d_ACCESS_DESCRIPTION (ACCESS_DESCRIPTION* a, ubyte** out_);
extern __gshared const ASN1_ITEM ACCESS_DESCRIPTION_it;
AUTHORITY_INFO_ACCESS* AUTHORITY_INFO_ACCESS_new ();
void AUTHORITY_INFO_ACCESS_free (AUTHORITY_INFO_ACCESS* a);
AUTHORITY_INFO_ACCESS* d2i_AUTHORITY_INFO_ACCESS (AUTHORITY_INFO_ACCESS** a, const(ubyte*)* in_, c_long len);
int i2d_AUTHORITY_INFO_ACCESS (AUTHORITY_INFO_ACCESS* a, ubyte** out_);
extern __gshared const ASN1_ITEM AUTHORITY_INFO_ACCESS_it;
extern __gshared const ASN1_ITEM POLICY_MAPPING_it;
POLICY_MAPPING* POLICY_MAPPING_new ();
void POLICY_MAPPING_free (POLICY_MAPPING* a);
extern __gshared const ASN1_ITEM POLICY_MAPPINGS_it;

extern __gshared const ASN1_ITEM GENERAL_SUBTREE_it;
GENERAL_SUBTREE* GENERAL_SUBTREE_new ();
void GENERAL_SUBTREE_free (GENERAL_SUBTREE* a);

extern __gshared const ASN1_ITEM NAME_CONSTRAINTS_it;
NAME_CONSTRAINTS* NAME_CONSTRAINTS_new ();
void NAME_CONSTRAINTS_free (NAME_CONSTRAINTS* a);

POLICY_CONSTRAINTS* POLICY_CONSTRAINTS_new ();
void POLICY_CONSTRAINTS_free (POLICY_CONSTRAINTS* a);
extern __gshared const ASN1_ITEM POLICY_CONSTRAINTS_it;

GENERAL_NAME* a2i_GENERAL_NAME (
    GENERAL_NAME* out_,
    const(X509V3_EXT_METHOD)* method,
    X509V3_CTX* ctx,
    int gen_type,
    const(char)* value,
    int is_nc);

GENERAL_NAME* v2i_GENERAL_NAME (
    const(X509V3_EXT_METHOD)* method,
    X509V3_CTX* ctx,
    CONF_VALUE* cnf);
GENERAL_NAME* v2i_GENERAL_NAME_ex (
    GENERAL_NAME* out_,
    const(X509V3_EXT_METHOD)* method,
    X509V3_CTX* ctx,
    CONF_VALUE* cnf,
    int is_nc);
void X509V3_conf_free (CONF_VALUE* val);

X509_EXTENSION* X509V3_EXT_nconf_nid (
    CONF* conf,
    X509V3_CTX* ctx,
    int ext_nid,
    const(char)* value);
X509_EXTENSION* X509V3_EXT_nconf (
    CONF* conf,
    X509V3_CTX* ctx,
    const(char)* name,
    const(char)* value);
int X509V3_EXT_add_nconf_sk (
    CONF* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    stack_st_X509_EXTENSION** sk);
int X509V3_EXT_add_nconf (
    CONF* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    X509* cert);
int X509V3_EXT_REQ_add_nconf (
    CONF* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    X509_REQ* req);
int X509V3_EXT_CRL_add_nconf (
    CONF* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    X509_CRL* crl);

X509_EXTENSION* X509V3_EXT_conf_nid (
    lhash_st_CONF_VALUE* conf,
    X509V3_CTX* ctx,
    int ext_nid,
    const(char)* value);
X509_EXTENSION* X509V3_EXT_conf (
    lhash_st_CONF_VALUE* conf,
    X509V3_CTX* ctx,
    const(char)* name,
    const(char)* value);
int X509V3_EXT_add_conf (
    lhash_st_CONF_VALUE* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    X509* cert);
int X509V3_EXT_REQ_add_conf (
    lhash_st_CONF_VALUE* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    X509_REQ* req);
int X509V3_EXT_CRL_add_conf (
    lhash_st_CONF_VALUE* conf,
    X509V3_CTX* ctx,
    const(char)* section,
    X509_CRL* crl);

int X509V3_add_value_bool_nf (
    const(char)* name,
    int asn1_bool,
    stack_st_CONF_VALUE** extlist);
int X509V3_get_value_bool (const(CONF_VALUE)* value, int* asn1_bool);
int X509V3_get_value_int (const(CONF_VALUE)* value, ASN1_INTEGER** aint);
void X509V3_set_nconf (X509V3_CTX* ctx, CONF* conf);
void X509V3_set_conf_lhash (X509V3_CTX* ctx, lhash_st_CONF_VALUE* lhash);

char* X509V3_get_string (X509V3_CTX* ctx, const(char)* name, const(char)* section);
stack_st_CONF_VALUE* X509V3_get_section (X509V3_CTX* ctx, const(char)* section);
void X509V3_string_free (X509V3_CTX* ctx, char* str);
void X509V3_section_free (X509V3_CTX* ctx, stack_st_CONF_VALUE* section);
void X509V3_set_ctx (
    X509V3_CTX* ctx,
    X509* issuer,
    X509* subject,
    X509_REQ* req,
    X509_CRL* crl,
    int flags);

int X509V3_add_value (
    const(char)* name,
    const(char)* value,
    stack_st_CONF_VALUE** extlist);
int X509V3_add_value_uchar (
    const(char)* name,
    const(ubyte)* value,
    stack_st_CONF_VALUE** extlist);
int X509V3_add_value_bool (
    const(char)* name,
    int asn1_bool,
    stack_st_CONF_VALUE** extlist);
int X509V3_add_value_int (
    const(char)* name,
    const(ASN1_INTEGER)* aint,
    stack_st_CONF_VALUE** extlist);
char* i2s_ASN1_INTEGER (X509V3_EXT_METHOD* meth, const(ASN1_INTEGER)* aint);
ASN1_INTEGER* s2i_ASN1_INTEGER (X509V3_EXT_METHOD* meth, const(char)* value);
char* i2s_ASN1_ENUMERATED (X509V3_EXT_METHOD* meth, const(ASN1_ENUMERATED)* aint);
char* i2s_ASN1_ENUMERATED_TABLE (
    X509V3_EXT_METHOD* meth,
    const(ASN1_ENUMERATED)* aint);
int X509V3_EXT_add (X509V3_EXT_METHOD* ext);
int X509V3_EXT_add_list (X509V3_EXT_METHOD* extlist);
int X509V3_EXT_add_alias (int nid_to, int nid_from);
void X509V3_EXT_cleanup ();

const(X509V3_EXT_METHOD)* X509V3_EXT_get (X509_EXTENSION* ext);
const(X509V3_EXT_METHOD)* X509V3_EXT_get_nid (int nid);
int X509V3_add_standard_extensions ();
stack_st_CONF_VALUE* X509V3_parse_list (const(char)* line);
void* X509V3_EXT_d2i (X509_EXTENSION* ext);
void* X509V3_get_d2i (
    const(stack_st_X509_EXTENSION)* x,
    int nid,
    int* crit,
    int* idx);

X509_EXTENSION* X509V3_EXT_i2d (int ext_nid, int crit, void* ext_struc);
int X509V3_add1_i2d (
    stack_st_X509_EXTENSION** x,
    int nid,
    void* value,
    int crit,
    c_ulong flags);

/* The new declarations are in crypto.h, but the old ones were here. */
alias hex_to_string = OPENSSL_buf2hexstr;
alias string_to_hex = OPENSSL_hexstr2buf;

void X509V3_EXT_val_prn (
    BIO* out_,
    stack_st_CONF_VALUE* val,
    int indent,
    int ml);
int X509V3_EXT_print (BIO* out_, X509_EXTENSION* ext, c_ulong flag, int indent);

int X509V3_EXT_print_fp (FILE* out_, X509_EXTENSION* ext, int flag, int indent);

int X509V3_extensions_print (
    BIO* out_,
    const(char)* title,
    const(stack_st_X509_EXTENSION)* exts,
    c_ulong flag,
    int indent);

int X509_check_ca (X509* x);
int X509_check_purpose (X509* x, int id, int ca);
int X509_supported_extension (X509_EXTENSION* ex);
int X509_PURPOSE_set (int* p, int purpose);
int X509_check_issued (X509* issuer, X509* subject);
int X509_check_akid (X509* issuer, AUTHORITY_KEYID* akid);
void X509_set_proxy_flag (X509* x);
void X509_set_proxy_pathlen (X509* x, c_long l);
c_long X509_get_proxy_pathlen (X509* x);

uint X509_get_extension_flags (X509* x);
uint X509_get_key_usage (X509* x);
uint X509_get_extended_key_usage (X509* x);
const(ASN1_OCTET_STRING)* X509_get0_subject_key_id (X509* x);
const(ASN1_OCTET_STRING)* X509_get0_authority_key_id (X509* x);

int X509_PURPOSE_get_count ();
X509_PURPOSE* X509_PURPOSE_get0 (int idx);
int X509_PURPOSE_get_by_sname (const(char)* sname);
int X509_PURPOSE_get_by_id (int id);
int X509_PURPOSE_add (
    int id,
    int trust,
    int flags,
    int function (const(X509_PURPOSE)*, const(X509)*, int) ck,
    const(char)* name,
    const(char)* sname,
    void* arg);
char* X509_PURPOSE_get0_name (const(X509_PURPOSE)* xp);
char* X509_PURPOSE_get0_sname (const(X509_PURPOSE)* xp);
int X509_PURPOSE_get_trust (const(X509_PURPOSE)* xp);
void X509_PURPOSE_cleanup ();
int X509_PURPOSE_get_id (const(X509_PURPOSE)*);

stack_st_OPENSSL_STRING* X509_get1_email (X509* x);
stack_st_OPENSSL_STRING* X509_REQ_get1_email (X509_REQ* x);
void X509_email_free (stack_st_OPENSSL_STRING* sk);
stack_st_OPENSSL_STRING* X509_get1_ocsp (X509* x);
/* Flags for X509_check_* functions */

/*
 * Always check subject name for host match even if subject alt names present
 */
enum X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT = 0x1;
/* Disable wildcard matching for dnsName fields and common name. */
enum X509_CHECK_FLAG_NO_WILDCARDS = 0x2;
/* Wildcards must not match a partial label. */
enum X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x4;
/* Allow (non-partial) wildcards to match multiple labels. */
enum X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS = 0x8;
/* Constraint verifier subdomain patterns to match a single labels. */
enum X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS = 0x10;
/* Never check the subject CN */
enum X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0x20;
/*
 * Match reference identifiers starting with "." to any sub-domain.
 * This is a non-public flag, turned on implicitly when the subject
 * reference identity is a DNS name.
 */
enum _X509_CHECK_FLAG_DOT_SUBDOMAINS = 0x8000;

int X509_check_host (
    X509* x,
    const(char)* chk,
    size_t chklen,
    uint flags,
    char** peername);
int X509_check_email (X509* x, const(char)* chk, size_t chklen, uint flags);
int X509_check_ip (X509* x, const(ubyte)* chk, size_t chklen, uint flags);
int X509_check_ip_asc (X509* x, const(char)* ipasc, uint flags);

ASN1_OCTET_STRING* a2i_IPADDRESS (const(char)* ipasc);
ASN1_OCTET_STRING* a2i_IPADDRESS_NC (const(char)* ipasc);
int X509V3_NAME_from_section (
    X509_NAME* nm,
    stack_st_CONF_VALUE* dn_sk,
    c_ulong chtype);

void X509_POLICY_NODE_print (BIO* out_, X509_POLICY_NODE* node, int indent);
struct stack_st_X509_POLICY_NODE;
alias sk_X509_POLICY_NODE_compfunc = int function (const(X509_POLICY_NODE*)* a, const(X509_POLICY_NODE*)* b);
alias sk_X509_POLICY_NODE_freefunc = void function (X509_POLICY_NODE* a);
alias sk_X509_POLICY_NODE_copyfunc = X509_POLICY_NODE_st* function (const(X509_POLICY_NODE)* a);
int sk_X509_POLICY_NODE_num (const(stack_st_X509_POLICY_NODE)* sk);
X509_POLICY_NODE* sk_X509_POLICY_NODE_value (const(stack_st_X509_POLICY_NODE)* sk, int idx);
stack_st_X509_POLICY_NODE* sk_X509_POLICY_NODE_new (sk_X509_POLICY_NODE_compfunc compare);
stack_st_X509_POLICY_NODE* sk_X509_POLICY_NODE_new_null ();
void sk_X509_POLICY_NODE_free (stack_st_X509_POLICY_NODE* sk);
void sk_X509_POLICY_NODE_zero (stack_st_X509_POLICY_NODE* sk);
X509_POLICY_NODE* sk_X509_POLICY_NODE_delete (stack_st_X509_POLICY_NODE* sk, int i);
X509_POLICY_NODE* sk_X509_POLICY_NODE_delete_ptr (stack_st_X509_POLICY_NODE* sk, X509_POLICY_NODE* ptr);
int sk_X509_POLICY_NODE_push (stack_st_X509_POLICY_NODE* sk, X509_POLICY_NODE* ptr);
int sk_X509_POLICY_NODE_unshift (stack_st_X509_POLICY_NODE* sk, X509_POLICY_NODE* ptr);
X509_POLICY_NODE* sk_X509_POLICY_NODE_pop (stack_st_X509_POLICY_NODE* sk);
X509_POLICY_NODE* sk_X509_POLICY_NODE_shift (stack_st_X509_POLICY_NODE* sk);
void sk_X509_POLICY_NODE_pop_free (stack_st_X509_POLICY_NODE* sk, sk_X509_POLICY_NODE_freefunc freefunc);
int sk_X509_POLICY_NODE_insert (stack_st_X509_POLICY_NODE* sk, X509_POLICY_NODE* ptr, int idx);
X509_POLICY_NODE* sk_X509_POLICY_NODE_set (stack_st_X509_POLICY_NODE* sk, int idx, X509_POLICY_NODE* ptr);
int sk_X509_POLICY_NODE_find (stack_st_X509_POLICY_NODE* sk, X509_POLICY_NODE* ptr);
int sk_X509_POLICY_NODE_find_ex (stack_st_X509_POLICY_NODE* sk, X509_POLICY_NODE* ptr);
void sk_X509_POLICY_NODE_sort (stack_st_X509_POLICY_NODE* sk);
int sk_X509_POLICY_NODE_is_sorted (const(stack_st_X509_POLICY_NODE)* sk);
stack_st_X509_POLICY_NODE* sk_X509_POLICY_NODE_dup (const(stack_st_X509_POLICY_NODE)* sk);
stack_st_X509_POLICY_NODE* sk_X509_POLICY_NODE_deep_copy (const(stack_st_X509_POLICY_NODE)* sk, sk_X509_POLICY_NODE_copyfunc copyfunc, sk_X509_POLICY_NODE_freefunc freefunc);
sk_X509_POLICY_NODE_compfunc sk_X509_POLICY_NODE_set_cmp_func (stack_st_X509_POLICY_NODE* sk, sk_X509_POLICY_NODE_compfunc compare);

version(OPENSSL_NO_RFC3779) {} else {
struct ASRange_st
{
    ASN1_INTEGER* min;
    ASN1_INTEGER* max;
}
}
alias ASRange = ASRange_st;

enum ASIdOrRange_id = 0;
enum ASIdOrRange_range = 1;

struct ASIdOrRange_st
{
    int type;

    union _Anonymous_3
    {
        ASN1_INTEGER* id;
        ASRange* range;
    }

    _Anonymous_3 u;
}

alias ASIdOrRange = ASIdOrRange_st;

struct stack_st_ASIdOrRange;
alias ASIdOrRanges = stack_st_ASIdOrRange;
alias sk_ASIdOrRange_compfunc = int function (const(ASIdOrRange*)* a, const(ASIdOrRange*)* b);
alias sk_ASIdOrRange_freefunc = void function (ASIdOrRange* a);
alias sk_ASIdOrRange_copyfunc = ASIdOrRange_st* function (const(ASIdOrRange)* a);
int sk_ASIdOrRange_num (const(stack_st_ASIdOrRange)* sk);
ASIdOrRange* sk_ASIdOrRange_value (const(stack_st_ASIdOrRange)* sk, int idx);
stack_st_ASIdOrRange* sk_ASIdOrRange_new (sk_ASIdOrRange_compfunc compare);
stack_st_ASIdOrRange* sk_ASIdOrRange_new_null ();
void sk_ASIdOrRange_free (stack_st_ASIdOrRange* sk);
void sk_ASIdOrRange_zero (stack_st_ASIdOrRange* sk);
ASIdOrRange* sk_ASIdOrRange_delete (stack_st_ASIdOrRange* sk, int i);
ASIdOrRange* sk_ASIdOrRange_delete_ptr (stack_st_ASIdOrRange* sk, ASIdOrRange* ptr);
int sk_ASIdOrRange_push (stack_st_ASIdOrRange* sk, ASIdOrRange* ptr);
int sk_ASIdOrRange_unshift (stack_st_ASIdOrRange* sk, ASIdOrRange* ptr);
ASIdOrRange* sk_ASIdOrRange_pop (stack_st_ASIdOrRange* sk);
ASIdOrRange* sk_ASIdOrRange_shift (stack_st_ASIdOrRange* sk);
void sk_ASIdOrRange_pop_free (stack_st_ASIdOrRange* sk, sk_ASIdOrRange_freefunc freefunc);
int sk_ASIdOrRange_insert (stack_st_ASIdOrRange* sk, ASIdOrRange* ptr, int idx);
ASIdOrRange* sk_ASIdOrRange_set (stack_st_ASIdOrRange* sk, int idx, ASIdOrRange* ptr);
int sk_ASIdOrRange_find (stack_st_ASIdOrRange* sk, ASIdOrRange* ptr);
int sk_ASIdOrRange_find_ex (stack_st_ASIdOrRange* sk, ASIdOrRange* ptr);
void sk_ASIdOrRange_sort (stack_st_ASIdOrRange* sk);
int sk_ASIdOrRange_is_sorted (const(stack_st_ASIdOrRange)* sk);
stack_st_ASIdOrRange* sk_ASIdOrRange_dup (const(stack_st_ASIdOrRange)* sk);
stack_st_ASIdOrRange* sk_ASIdOrRange_deep_copy (const(stack_st_ASIdOrRange)* sk, sk_ASIdOrRange_copyfunc copyfunc, sk_ASIdOrRange_freefunc freefunc);
sk_ASIdOrRange_compfunc sk_ASIdOrRange_set_cmp_func (stack_st_ASIdOrRange* sk, sk_ASIdOrRange_compfunc compare);

enum ASIdentifierChoice_inherit = 0;
enum ASIdentifierChoice_asIdsOrRanges = 1;

struct ASIdentifierChoice_st
{
    int type;

    union _Anonymous_4
    {
        ASN1_NULL* inherit;
        ASIdOrRanges* asIdsOrRanges;
    }

    _Anonymous_4 u;
}

alias ASIdentifierChoice = ASIdentifierChoice_st;

struct ASIdentifiers_st
{
    ASIdentifierChoice* asnum;
    ASIdentifierChoice* rdi;
}

alias ASIdentifiers = ASIdentifiers_st;

ASRange* ASRange_new ();
void ASRange_free (ASRange* a);
ASRange* d2i_ASRange (ASRange** a, const(ubyte*)* in_, c_long len);
int i2d_ASRange (ASRange* a, ubyte** out_);
extern __gshared const ASN1_ITEM ASRange_it;
ASIdOrRange* ASIdOrRange_new ();
void ASIdOrRange_free (ASIdOrRange* a);
ASIdOrRange* d2i_ASIdOrRange (ASIdOrRange** a, const(ubyte*)* in_, c_long len);
int i2d_ASIdOrRange (ASIdOrRange* a, ubyte** out_);
extern __gshared const ASN1_ITEM ASIdOrRange_it;
ASIdentifierChoice* ASIdentifierChoice_new ();
void ASIdentifierChoice_free (ASIdentifierChoice* a);
ASIdentifierChoice* d2i_ASIdentifierChoice (ASIdentifierChoice** a, const(ubyte*)* in_, c_long len);
int i2d_ASIdentifierChoice (ASIdentifierChoice* a, ubyte** out_);
extern __gshared const ASN1_ITEM ASIdentifierChoice_it;
ASIdentifiers* ASIdentifiers_new ();
void ASIdentifiers_free (ASIdentifiers* a);
ASIdentifiers* d2i_ASIdentifiers (ASIdentifiers** a, const(ubyte*)* in_, c_long len);
int i2d_ASIdentifiers (ASIdentifiers* a, ubyte** out_);
extern __gshared const ASN1_ITEM ASIdentifiers_it;

struct IPAddressRange_st
{
    ASN1_BIT_STRING* min;
    ASN1_BIT_STRING* max;
}

alias IPAddressRange = IPAddressRange_st;

enum IPAddressOrRange_addressPrefix = 0;
enum IPAddressOrRange_addressRange = 1;

struct IPAddressOrRange_st
{
    int type;

    union _Anonymous_5
    {
        ASN1_BIT_STRING* addressPrefix;
        IPAddressRange* addressRange;
    }

    _Anonymous_5 u;
}

alias IPAddressOrRange = IPAddressOrRange_st;

struct stack_st_IPAddressOrRange;
alias IPAddressOrRanges = stack_st_IPAddressOrRange;
alias sk_IPAddressOrRange_compfunc = int function (const(IPAddressOrRange*)* a, const(IPAddressOrRange*)* b);
alias sk_IPAddressOrRange_freefunc = void function (IPAddressOrRange* a);
alias sk_IPAddressOrRange_copyfunc = IPAddressOrRange_st* function (const(IPAddressOrRange)* a);
int sk_IPAddressOrRange_num (const(stack_st_IPAddressOrRange)* sk);
IPAddressOrRange* sk_IPAddressOrRange_value (const(stack_st_IPAddressOrRange)* sk, int idx);
stack_st_IPAddressOrRange* sk_IPAddressOrRange_new (sk_IPAddressOrRange_compfunc compare);
stack_st_IPAddressOrRange* sk_IPAddressOrRange_new_null ();
void sk_IPAddressOrRange_free (stack_st_IPAddressOrRange* sk);
void sk_IPAddressOrRange_zero (stack_st_IPAddressOrRange* sk);
IPAddressOrRange* sk_IPAddressOrRange_delete (stack_st_IPAddressOrRange* sk, int i);
IPAddressOrRange* sk_IPAddressOrRange_delete_ptr (stack_st_IPAddressOrRange* sk, IPAddressOrRange* ptr);
int sk_IPAddressOrRange_push (stack_st_IPAddressOrRange* sk, IPAddressOrRange* ptr);
int sk_IPAddressOrRange_unshift (stack_st_IPAddressOrRange* sk, IPAddressOrRange* ptr);
IPAddressOrRange* sk_IPAddressOrRange_pop (stack_st_IPAddressOrRange* sk);
IPAddressOrRange* sk_IPAddressOrRange_shift (stack_st_IPAddressOrRange* sk);
void sk_IPAddressOrRange_pop_free (stack_st_IPAddressOrRange* sk, sk_IPAddressOrRange_freefunc freefunc);
int sk_IPAddressOrRange_insert (stack_st_IPAddressOrRange* sk, IPAddressOrRange* ptr, int idx);
IPAddressOrRange* sk_IPAddressOrRange_set (stack_st_IPAddressOrRange* sk, int idx, IPAddressOrRange* ptr);
int sk_IPAddressOrRange_find (stack_st_IPAddressOrRange* sk, IPAddressOrRange* ptr);
int sk_IPAddressOrRange_find_ex (stack_st_IPAddressOrRange* sk, IPAddressOrRange* ptr);
void sk_IPAddressOrRange_sort (stack_st_IPAddressOrRange* sk);
int sk_IPAddressOrRange_is_sorted (const(stack_st_IPAddressOrRange)* sk);
stack_st_IPAddressOrRange* sk_IPAddressOrRange_dup (const(stack_st_IPAddressOrRange)* sk);
stack_st_IPAddressOrRange* sk_IPAddressOrRange_deep_copy (const(stack_st_IPAddressOrRange)* sk, sk_IPAddressOrRange_copyfunc copyfunc, sk_IPAddressOrRange_freefunc freefunc);
sk_IPAddressOrRange_compfunc sk_IPAddressOrRange_set_cmp_func (stack_st_IPAddressOrRange* sk, sk_IPAddressOrRange_compfunc compare);

enum IPAddressChoice_inherit = 0;
enum IPAddressChoice_addressesOrRanges = 1;

struct IPAddressChoice_st
{
    int type;

    union _Anonymous_6
    {
        ASN1_NULL* inherit;
        IPAddressOrRanges* addressesOrRanges;
    }

    _Anonymous_6 u;
}

alias IPAddressChoice = IPAddressChoice_st;

struct IPAddressFamily_st
{
    ASN1_OCTET_STRING* addressFamily;
    IPAddressChoice* ipAddressChoice;
}

alias IPAddressFamily = IPAddressFamily_st;

struct stack_st_IPAddressFamily;
alias IPAddrBlocks = stack_st_IPAddressFamily;
alias sk_IPAddressFamily_compfunc = int function (const(IPAddressFamily*)* a, const(IPAddressFamily*)* b);
alias sk_IPAddressFamily_freefunc = void function (IPAddressFamily* a);
alias sk_IPAddressFamily_copyfunc = IPAddressFamily_st* function (const(IPAddressFamily)* a);
int sk_IPAddressFamily_num (const(stack_st_IPAddressFamily)* sk);
IPAddressFamily* sk_IPAddressFamily_value (const(stack_st_IPAddressFamily)* sk, int idx);
stack_st_IPAddressFamily* sk_IPAddressFamily_new (sk_IPAddressFamily_compfunc compare);
stack_st_IPAddressFamily* sk_IPAddressFamily_new_null ();
void sk_IPAddressFamily_free (stack_st_IPAddressFamily* sk);
void sk_IPAddressFamily_zero (stack_st_IPAddressFamily* sk);
IPAddressFamily* sk_IPAddressFamily_delete (stack_st_IPAddressFamily* sk, int i);
IPAddressFamily* sk_IPAddressFamily_delete_ptr (stack_st_IPAddressFamily* sk, IPAddressFamily* ptr);
int sk_IPAddressFamily_push (stack_st_IPAddressFamily* sk, IPAddressFamily* ptr);
int sk_IPAddressFamily_unshift (stack_st_IPAddressFamily* sk, IPAddressFamily* ptr);
IPAddressFamily* sk_IPAddressFamily_pop (stack_st_IPAddressFamily* sk);
IPAddressFamily* sk_IPAddressFamily_shift (stack_st_IPAddressFamily* sk);
void sk_IPAddressFamily_pop_free (stack_st_IPAddressFamily* sk, sk_IPAddressFamily_freefunc freefunc);
int sk_IPAddressFamily_insert (stack_st_IPAddressFamily* sk, IPAddressFamily* ptr, int idx);
IPAddressFamily* sk_IPAddressFamily_set (stack_st_IPAddressFamily* sk, int idx, IPAddressFamily* ptr);
int sk_IPAddressFamily_find (stack_st_IPAddressFamily* sk, IPAddressFamily* ptr);
int sk_IPAddressFamily_find_ex (stack_st_IPAddressFamily* sk, IPAddressFamily* ptr);
void sk_IPAddressFamily_sort (stack_st_IPAddressFamily* sk);
int sk_IPAddressFamily_is_sorted (const(stack_st_IPAddressFamily)* sk);
stack_st_IPAddressFamily* sk_IPAddressFamily_dup (const(stack_st_IPAddressFamily)* sk);
stack_st_IPAddressFamily* sk_IPAddressFamily_deep_copy (const(stack_st_IPAddressFamily)* sk, sk_IPAddressFamily_copyfunc copyfunc, sk_IPAddressFamily_freefunc freefunc);
sk_IPAddressFamily_compfunc sk_IPAddressFamily_set_cmp_func (stack_st_IPAddressFamily* sk, sk_IPAddressFamily_compfunc compare);

IPAddressRange* IPAddressRange_new ();
void IPAddressRange_free (IPAddressRange* a);
IPAddressRange* d2i_IPAddressRange (IPAddressRange** a, const(ubyte*)* in_, c_long len);
int i2d_IPAddressRange (IPAddressRange* a, ubyte** out_);
extern __gshared const ASN1_ITEM IPAddressRange_it;
IPAddressOrRange* IPAddressOrRange_new ();
void IPAddressOrRange_free (IPAddressOrRange* a);
IPAddressOrRange* d2i_IPAddressOrRange (IPAddressOrRange** a, const(ubyte*)* in_, c_long len);
int i2d_IPAddressOrRange (IPAddressOrRange* a, ubyte** out_);
extern __gshared const ASN1_ITEM IPAddressOrRange_it;
IPAddressChoice* IPAddressChoice_new ();
void IPAddressChoice_free (IPAddressChoice* a);
IPAddressChoice* d2i_IPAddressChoice (IPAddressChoice** a, const(ubyte*)* in_, c_long len);
int i2d_IPAddressChoice (IPAddressChoice* a, ubyte** out_);
extern __gshared const ASN1_ITEM IPAddressChoice_it;
IPAddressFamily* IPAddressFamily_new ();
void IPAddressFamily_free (IPAddressFamily* a);
IPAddressFamily* d2i_IPAddressFamily (IPAddressFamily** a, const(ubyte*)* in_, c_long len);
int i2d_IPAddressFamily (IPAddressFamily* a, ubyte** out_);
extern __gshared const ASN1_ITEM IPAddressFamily_it;

/*
 * API tag for elements of the ASIdentifer SEQUENCE.
 */
enum V3_ASID_ASNUM = 0;
enum V3_ASID_RDI = 1;

/*
 * AFI values, assigned by IANA.  It'd be nice to make the AFI
 * handling code totally generic, but there are too many little things
 * that would need to be defined for other address families for it to
 * be worth the trouble.
 */
enum IANA_AFI_IPV4 = 1;
enum IANA_AFI_IPV6 = 2;

/*
 * Utilities to construct and extract values from RFC3779 extensions,
 * since some of the encodings (particularly for IP address prefixes
 * and ranges) are a bit tedious to work with directly.
 */
int X509v3_asid_add_inherit (ASIdentifiers* asid, int which);
int X509v3_asid_add_id_or_range (
    ASIdentifiers* asid,
    int which,
    ASN1_INTEGER* min,
    ASN1_INTEGER* max);
int X509v3_addr_add_inherit (
    IPAddrBlocks* addr,
    const uint afi,
    const(uint)* safi);
int X509v3_addr_add_prefix (
    IPAddrBlocks* addr,
    const uint afi,
    const(uint)* safi,
    ubyte* a,
    const int prefixlen);
int X509v3_addr_add_range (
    IPAddrBlocks* addr,
    const uint afi,
    const(uint)* safi,
    ubyte* min,
    ubyte* max);
uint X509v3_addr_get_afi (const(IPAddressFamily)* f);
int X509v3_addr_get_range (
    IPAddressOrRange* aor,
    const uint afi,
    ubyte* min,
    ubyte* max,
    const int length);

/*
 * Canonical forms.
 */
int X509v3_asid_is_canonical (ASIdentifiers* asid);
int X509v3_addr_is_canonical (IPAddrBlocks* addr);
int X509v3_asid_canonize (ASIdentifiers* asid);
int X509v3_addr_canonize (IPAddrBlocks* addr);

/*
 * Tests for inheritance and containment.
 */
int X509v3_asid_inherits (ASIdentifiers* asid);
int X509v3_addr_inherits (IPAddrBlocks* addr);
int X509v3_asid_subset (ASIdentifiers* a, ASIdentifiers* b);
int X509v3_addr_subset (IPAddrBlocks* a, IPAddrBlocks* b);

/*
 * Check whether RFC 3779 extensions nest properly in chains.
 */
int X509v3_asid_validate_path (X509_STORE_CTX*);
int X509v3_addr_validate_path (X509_STORE_CTX*);
int X509v3_asid_validate_resource_set (
    stack_st_X509* chain,
    ASIdentifiers* ext,
    int allow_inheritance);
int X509v3_addr_validate_resource_set (
    stack_st_X509* chain,
    IPAddrBlocks* ext,
    int allow_inheritance);

/* OPENSSL_NO_RFC3779 */

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_X509V3_strings ();

/* Error codes for the X509V3 functions. */

/* Function codes. */
enum X509V3_F_A2I_GENERAL_NAME = 164;
enum X509V3_F_ADDR_VALIDATE_PATH_INTERNAL = 166;
enum X509V3_F_ASIDENTIFIERCHOICE_CANONIZE = 161;
enum X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL = 162;
enum X509V3_F_BIGNUM_TO_STRING = 167;
enum X509V3_F_COPY_EMAIL = 122;
enum X509V3_F_COPY_ISSUER = 123;
enum X509V3_F_DO_DIRNAME = 144;
enum X509V3_F_DO_EXT_I2D = 135;
enum X509V3_F_DO_EXT_NCONF = 151;
enum X509V3_F_GNAMES_FROM_SECTNAME = 156;
enum X509V3_F_I2S_ASN1_ENUMERATED = 121;
enum X509V3_F_I2S_ASN1_IA5STRING = 149;
enum X509V3_F_I2S_ASN1_INTEGER = 120;
enum X509V3_F_I2V_AUTHORITY_INFO_ACCESS = 138;
enum X509V3_F_NOTICE_SECTION = 132;
enum X509V3_F_NREF_NOS = 133;
enum X509V3_F_POLICY_SECTION = 131;
enum X509V3_F_PROCESS_PCI_VALUE = 150;
enum X509V3_F_R2I_CERTPOL = 130;
enum X509V3_F_R2I_PCI = 155;
enum X509V3_F_S2I_ASN1_IA5STRING = 100;
enum X509V3_F_S2I_ASN1_INTEGER = 108;
enum X509V3_F_S2I_ASN1_OCTET_STRING = 112;
enum X509V3_F_S2I_SKEY_ID = 115;
enum X509V3_F_SET_DIST_POINT_NAME = 158;
enum X509V3_F_SXNET_ADD_ID_ASC = 125;
enum X509V3_F_SXNET_ADD_ID_INTEGER = 126;
enum X509V3_F_SXNET_ADD_ID_ULONG = 127;
enum X509V3_F_SXNET_GET_ID_ASC = 128;
enum X509V3_F_SXNET_GET_ID_ULONG = 129;
enum X509V3_F_V2I_ASIDENTIFIERS = 163;
enum X509V3_F_V2I_ASN1_BIT_STRING = 101;
enum X509V3_F_V2I_AUTHORITY_INFO_ACCESS = 139;
enum X509V3_F_V2I_AUTHORITY_KEYID = 119;
enum X509V3_F_V2I_BASIC_CONSTRAINTS = 102;
enum X509V3_F_V2I_CRLD = 134;
enum X509V3_F_V2I_EXTENDED_KEY_USAGE = 103;
enum X509V3_F_V2I_GENERAL_NAMES = 118;
enum X509V3_F_V2I_GENERAL_NAME_EX = 117;
enum X509V3_F_V2I_IDP = 157;
enum X509V3_F_V2I_IPADDRBLOCKS = 159;
enum X509V3_F_V2I_ISSUER_ALT = 153;
enum X509V3_F_V2I_NAME_CONSTRAINTS = 147;
enum X509V3_F_V2I_POLICY_CONSTRAINTS = 146;
enum X509V3_F_V2I_POLICY_MAPPINGS = 145;
enum X509V3_F_V2I_SUBJECT_ALT = 154;
enum X509V3_F_V2I_TLS_FEATURE = 165;
enum X509V3_F_V3_GENERIC_EXTENSION = 116;
enum X509V3_F_X509V3_ADD1_I2D = 140;
enum X509V3_F_X509V3_ADD_VALUE = 105;
enum X509V3_F_X509V3_EXT_ADD = 104;
enum X509V3_F_X509V3_EXT_ADD_ALIAS = 106;
enum X509V3_F_X509V3_EXT_I2D = 136;
enum X509V3_F_X509V3_EXT_NCONF = 152;
enum X509V3_F_X509V3_GET_SECTION = 142;
enum X509V3_F_X509V3_GET_STRING = 143;
enum X509V3_F_X509V3_GET_VALUE_BOOL = 110;
enum X509V3_F_X509V3_PARSE_LIST = 109;
enum X509V3_F_X509_PURPOSE_ADD = 137;
enum X509V3_F_X509_PURPOSE_SET = 141;

/* Reason codes. */
enum X509V3_R_BAD_IP_ADDRESS = 118;
enum X509V3_R_BAD_OBJECT = 119;
enum X509V3_R_BN_DEC2BN_ERROR = 100;
enum X509V3_R_BN_TO_ASN1_INTEGER_ERROR = 101;
enum X509V3_R_DIRNAME_ERROR = 149;
enum X509V3_R_DISTPOINT_ALREADY_SET = 160;
enum X509V3_R_DUPLICATE_ZONE_ID = 133;
enum X509V3_R_ERROR_CONVERTING_ZONE = 131;
enum X509V3_R_ERROR_CREATING_EXTENSION = 144;
enum X509V3_R_ERROR_IN_EXTENSION = 128;
enum X509V3_R_EXPECTED_A_SECTION_NAME = 137;
enum X509V3_R_EXTENSION_EXISTS = 145;
enum X509V3_R_EXTENSION_NAME_ERROR = 115;
enum X509V3_R_EXTENSION_NOT_FOUND = 102;
enum X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED = 103;
enum X509V3_R_EXTENSION_VALUE_ERROR = 116;
enum X509V3_R_ILLEGAL_EMPTY_EXTENSION = 151;
enum X509V3_R_INCORRECT_POLICY_SYNTAX_TAG = 152;
enum X509V3_R_INVALID_ASNUMBER = 162;
enum X509V3_R_INVALID_ASRANGE = 163;
enum X509V3_R_INVALID_BOOLEAN_STRING = 104;
enum X509V3_R_INVALID_EXTENSION_STRING = 105;
enum X509V3_R_INVALID_INHERITANCE = 165;
enum X509V3_R_INVALID_IPADDRESS = 166;
enum X509V3_R_INVALID_MULTIPLE_RDNS = 161;
enum X509V3_R_INVALID_NAME = 106;
enum X509V3_R_INVALID_NULL_ARGUMENT = 107;
enum X509V3_R_INVALID_NULL_NAME = 108;
enum X509V3_R_INVALID_NULL_VALUE = 109;
enum X509V3_R_INVALID_NUMBER = 140;
enum X509V3_R_INVALID_NUMBERS = 141;
enum X509V3_R_INVALID_OBJECT_IDENTIFIER = 110;
enum X509V3_R_INVALID_OPTION = 138;
enum X509V3_R_INVALID_POLICY_IDENTIFIER = 134;
enum X509V3_R_INVALID_PROXY_POLICY_SETTING = 153;
enum X509V3_R_INVALID_PURPOSE = 146;
enum X509V3_R_INVALID_SAFI = 164;
enum X509V3_R_INVALID_SECTION = 135;
enum X509V3_R_INVALID_SYNTAX = 143;
enum X509V3_R_ISSUER_DECODE_ERROR = 126;
enum X509V3_R_MISSING_VALUE = 124;
enum X509V3_R_NEED_ORGANIZATION_AND_NUMBERS = 142;
enum X509V3_R_NO_CONFIG_DATABASE = 136;
enum X509V3_R_NO_ISSUER_CERTIFICATE = 121;
enum X509V3_R_NO_ISSUER_DETAILS = 127;
enum X509V3_R_NO_POLICY_IDENTIFIER = 139;
enum X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED = 154;
enum X509V3_R_NO_PUBLIC_KEY = 114;
enum X509V3_R_NO_SUBJECT_DETAILS = 125;
enum X509V3_R_OPERATION_NOT_DEFINED = 148;
enum X509V3_R_OTHERNAME_ERROR = 147;
enum X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED = 155;
enum X509V3_R_POLICY_PATH_LENGTH = 156;
enum X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED = 157;
enum X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY = 159;
enum X509V3_R_SECTION_NOT_FOUND = 150;
enum X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS = 122;
enum X509V3_R_UNABLE_TO_GET_ISSUER_KEYID = 123;
enum X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT = 111;
enum X509V3_R_UNKNOWN_EXTENSION = 129;
enum X509V3_R_UNKNOWN_EXTENSION_NAME = 130;
enum X509V3_R_UNKNOWN_OPTION = 120;
enum X509V3_R_UNSUPPORTED_OPTION = 117;
enum X509V3_R_UNSUPPORTED_TYPE = 167;
enum X509V3_R_USER_TOO_LONG = 132;

