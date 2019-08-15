# Summary

This instruction describes how to pragmatically upgrade the openssl d-bindings
to match the C-headers version, in this case current version is 1.1.0h.

## Steps

### Preparation

1. Get d-step tool with:
    ```
    curl \
        --location \
        https://github.com/jacob-carlborg/dstep/releases/download/v1.0.0/dstep-1.0.0-linux-x86_64.tar.xz \
        | tar -x --xz --location /usr/local/bin
    ```
   See more @ <https://github.com/jacob-carlborg/dstep/releases>.
2. Clone openssl with `git clone https://github.com/openssl/openssl` and
   checkout correct tag, example `cd openssl && git checkout OpenSSL_1_1_0h`.
3. Headers with suffix ".h.in" need to be parsed to .h before generation,
   Configure openssl with `./configure` and build generated file with 
   `make build_generated`.

### Check dependencies

A good approach is to convert the files in ascending order for no of
dependencies. Example when converting x509, use order: `x509_vfy.h` which
is used by 1 other file, `x509v3.h` is used by 3 other files, `x509.h`
is used by 11 other files.

```
grep -r 'include <openssl/x509_vfy.h>$' C/
grep -r 'include <openssl/x509v3.h>$' C/
grep -r 'include <openssl/x509.h>$' C/
```

### Generate module from C header

1. Generate d-module from the openssl c-header with
   `dstep --space-after-function-name=false -Iinclude/ include/openssl/<file>`. Commit the change.

### Manual patching

Below is a checklist for common known issues which needs manual work:

1. d-step doesn't resolve includes. Translate "import" statements from
   `#include` in header-file accordingly, and possible check in the old .d-file
   for special cases.
2. Function aliases in C-headers without argument list, example
   `#define alias-name function` are generated as enum types. This gives
   compilation error similar to "missing argument for parameter #1".
   Replace "enum" with "alias" accordingly.
3. Many struct definitions is removed, instead a declaration ia added into
   `ossl_typ.d`, Example `grep -r 'struct X509_pubkey_st' C/` shows that struct
   definition is removed from `x509.h` and instead a declaration is added in
   `ossl_typ.h`. Other types might be removed, check the header-file and adjust
   accordingly if the type is missing when compiling.
4. Check the header-file for "ifdef|ifndef", search for "OPENSSL_*" where some
   statements has historically been translated into "version" in d-modules.
5. Macros `STACK_OF`, `DEFINE_STACK_OF`: in version 1.1.0h the macro `STACK_OF`
   in `safestack.d` has changed. During generation it's properly expanded into
   a type prefixed with `stack_st`. Since other dependent modules might not be
   uplifted, a declaration sometimes need to be inserted to make it
   compile. It will result in "type missing "stack_st_...". Check in which
   header the macro `DEFINE_STACK_OF(<type>)` is defined in and manually add
   `struct stack_st_<type-name>` to make it compile. However these functions 
   will not work properly during linkage until `safestack.d` is uplifted,
   see macro `DEFINE_STACK_OF` in safestack.h.
   