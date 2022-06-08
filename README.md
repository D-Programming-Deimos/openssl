OpenSSL D interface
-------------------

From the OpenSSL website:

> The OpenSSL Project is a collaborative effort to develop a robust,
> commercial-grade, full-featured, and Open Source toolkit
> implementing the Secure Sockets Layer (SSL v2/v3) and Transport
> Layer Security (TLS v1) protocols as well as a full-strength general
> purpose cryptography library. The project is managed by a worldwide
> community of volunteers that use the Internet to communicate, plan,
> and develop the OpenSSL toolkit and its related documentation.

This repository contains D bindings for OpenSSL.

Status: Varies, depending on targeted OpenSSL version.

The OpenSSL headers are huge (>35k LOC) and make quite liberal use of the C
preprocessor, and thus a fully automatic translation is as desirable as
it is infeasible. This repository contains the result of a semi-automatic
approach, and while all header files have been ported (and successfully
compile), some preprocessor artifacts still need to be ported (currently
commented out and tagged with a `FIXME` note).

### Compatibility

The latest version (v3.x and later) of this package aims to provide compatibility with
[current versions of OpenSSL](https://www.openssl.org/news/changelog.html).

The supported versions are all versions available on non-EOL Ubuntu LTS,
which is roughly equivalent to a 10 years support.
For Ubuntu versions under standard support, the version can be checked online,
for example [here](https://packages.ubuntu.com/jammy/openssl).

|    Ubuntu version    | OpenSSL version | Supported until |
|:--------------------:|:---------------:|:---------------:|
| 14.04 (Trusty)  | [1.0.1f](https://web.archive.org/web/20161208174333/https://packages.ubuntu.com/trusty/openssl) | April 2024 |
| 16.04 (Xenial)  | [1.0.2g](https://web.archive.org/web/20161021100827/http://packages.ubuntu.com/xenial/openssl) | April 2026 |
| 18.04 (Bionic)  | [1.1.0g / 1.1.1](https://web.archive.org/web/20161021100827/http://packages.ubuntu.com/xenial/openssl) | April 2028 |
| 20.04 (Focal)  | [1.1.1f](https://web.archive.org/web/20210417090632/https://packages.ubuntu.com/focal/openssl) | April 2030 |
| 22.04 (Jammy)  | [3.0.2](https://web.archive.org/web/20220606092159/https://packages.ubuntu.com/jammy/openssl) | April 2032 |


To allow supporting multiple OpenSSL versions from the same D bindings,
a build script exists to detect the OpenSSL version on the host system,
which then writes a version file the bindings will use.
This script depends on `pkg-config` being present, and is automatically
invoked when building with `dub`.

Other build systems can invoke the script directly and compile those bindings
with `DeimosOpenSSLAutoDetect`.

When using Windows or wanting to avoid the script,
`dub` users should depend on the subconfiguration `library-manual-version`,
and define the version in their dub file (e.g. `"versions" : [ "DeimosOpenSSL_3_0" ]`).

A list of all available versions can be found in [deimos.openssl.opensslv](source/deimos/openssl/opensslv.d).

Only minor versions are listed, patch versions are binary compatible with one another.
We use "minor" and "patch" with the [intended SemVer meaning](https://semver.org/).
For example, 1.1.1g and 1.1.1a are two different patch releases of the same minor.
Since OpenSSL v3.0.0, correct SemVer versioning is used.

All users not using the script should define the version corresponding to their OpenSSL version.
In the event no version is defined, the bindings will default to v1.1.0h.

### License

The OpenSSL toolkit is under a dual license, i.e. both the conditions
of the OpenSSL License and the original SSLeay license apply to the toolkit.
See the OpenSSL distribution for details. These interface files are a derived
work and do not impose any additional restrictions.
