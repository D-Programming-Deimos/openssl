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

The latest version of this package aims to provide compatibility with
[current versions of OpenSSL](https://www.openssl.org/news/changelog.html);
to facilitate this, a build script will detect the OpenSSL version on the
host system and configure the bindings appropriately. This will be done
automatically when using these bindings with Dub.

### License

The OpenSSL toolkit is under a dual license, i.e. both the conditions
of the OpenSSL License and the original SSLeay license apply to the toolkit.
See the OpenSSL distribution for details. These interface files are a derived
work and do not impose any additional restrictions.
