/**
 * Module to deal with the library version being used
 *
 * This library provide bindings for a wide range of OpenSSL versions,
 * ranging from v0.9.x to v3.0.x. Some versions are not compatible with
 * one another, either due to different ABI or different behavior,
 * for example OpenSSL 1.0 requires initialization but later versions do not.
 *
 * While things tend to mostly work or error out while linking when the version
 * the bindings assume and the actually C library version are too different,
 * we prefer to try detecting the currently used version, and allow users
 * to specify the version explicitly, before falling back to the latest bindings
 */
module deimos.openssl.opensslv;

import deimos.openssl._d_util;

version (DeimosOpenSSL_1_0_0)
{
    // https://www.openssl.org/news/changelog.html#openssl-100
    // OpenSSL 1.0.0t was released 2015-12-03
    public enum OpenSSLVersion = parseOpenSSLVersion("1.0.0t");
}
else version (DeimosOpenSSL_1_0_1)
{
    // https://www.openssl.org/news/changelog.html#openssl-101
    // OpenSSL 1.0.1u was released 2016-09-22
    public enum OpenSSLVersion = parseOpenSSLVersion("1.0.1u");
}
else version (DeimosOpenSSL_1_0_2)
{
    // https://www.openssl.org/news/changelog.html#openssl-102
    // OpenSSL 1.0.2t was released 2019-09-10
    public enum OpenSSLVersion = parseOpenSSLVersion("1.0.2t");
}
else version (DeimosOpenSSL_1_1_0)
{
    // https://www.openssl.org/news/changelog.html#openssl-110
    // OpenSSL 1.1.0l was released 2019-09-10
    public enum OpenSSLVersion = parseOpenSSLVersion("1.1.0l");
}
else version (DeimosOpenSSL_1_1_1)
{
    // https://www.openssl.org/news/changelog.html#openssl-111
    // OpenSSL 1.1.1m was released 2021-12-14
    public enum OpenSSLVersion = parseOpenSSLVersion("1.1.1m");
}
else version (DeimosOpenSSL_3_0)
{
    // https://www.openssl.org/news/changelog.html#openssl-30
    // OpenSSL 3.0.3 was released 2022-05-03
    public enum OpenSSLVersion = parseOpenSSLVersion("3.0.3");
}
else version (DeimosOpenSSLAutoDetect)
{
    import deimos.openssl.version_;

    public enum OpenSSLVersion = parseOpenSSLVersion(OpenSSLTextVersion);
}
else
{
    // It was decided in https://github.com/D-Programming-Deimos/openssl/pull/66
    // that we should fall back to the latest supported version of the bindings,
    // should the user provide neither explicit version nor `DeimosOpenSSLAutoDetect`
    public enum OpenSSLVersion = parseOpenSSLVersion("1.1.0h");
}

// Publicly aliased above
private struct OpenSSLVersionStruct
{
    string text;
    uint major, minor, patch;
    int build;
}

private OpenSSLVersionStruct parseOpenSSLVersion()(string textVersion)
{
    OpenSSLVersionStruct v;

    import std.ascii : isDigit;
    import std.algorithm.iteration : splitter;
    import std.algorithm.searching : canFind;
    import std.conv : to;
    import std.range : dropExactly;

    v.text = textVersion;

    v.major = textVersion.splitter('.')
        .front.to!uint;
    assert (v.major >= 0);

    v.minor = textVersion.splitter('.')
        .dropExactly(1)
        .front.to!uint;
    assert (v.minor >= 0);

    // `std.algorithm.iteration : splitWhen` not usable at CT
    // so we're using `canFind`.
    string patchText = textVersion.splitter('.')
        .dropExactly(2).front;
    auto patchChar = patchText.canFind!(
        (dchar c) => !c.isDigit());

    v.patch = patchText[0 .. $ - patchChar].to!uint;
    assert (v.patch >= 0);

    if (patchChar)
    {
        v.build = (patchText[$ - 1] - '`');
        assert (v.build >= 0);
    }
    else
        v.build = 0;

    return v;
}

/* Numeric release version identifier:
 * MNNFFPPS: major minor fix patch status
 * The status nibble has one of the values 0 for development, 1 to e for betas
 * 1 to 14, and f for release.  The patch level is exactly that.
 * For example:
 * 0.9.3-dev	  0x00903000
 * 0.9.3-beta1	  0x00903001
 * 0.9.3-beta2-dev 0x00903002
 * 0.9.3-beta2    0x00903002 (same as ...beta2-dev)
 * 0.9.3	  0x0090300f
 * 0.9.3a	  0x0090301f
 * 0.9.4 	  0x0090400f
 * 1.2.3z	  0x102031af
 *
 * For continuity reasons (because 0.9.5 is already out, and is coded
 * 0x00905100), between 0.9.5 and 0.9.6 the coding of the patch level
 * part is slightly different, by setting the highest bit.  This means
 * that 0.9.5a looks like this: 0x0090581f.  At 0.9.6, we can start
 * with 0x0090600S...
 *
 * (Prior to 0.9.3-dev a different scheme was used: 0.9.2b is 0x0922.)
 * (Prior to 0.9.5a beta1, a different scheme was used: MMNNFFRBB for
 * major minor fix final patch/beta)
 */

/* Version macros for compile-time API version detection */
enum OPENSSL_VERSION_MAJOR   = OpenSSLVersion.major;

enum OPENSSL_VERSION_MINOR   = OpenSSLVersion.minor;

enum OPENSSL_VERSION_PATCH   = OpenSSLVersion.patch;

enum OPENSSL_VERSION_BUILD   = OpenSSLVersion.build;

int OPENSSL_MAKE_VERSION()(int major, int minor, int patch, int build)
{
    return (major << 28) | (minor << 20) | (patch << 12) | (build << 4) | 0xf;
}

enum OPENSSL_VERSION_NUMBER =
    OPENSSL_MAKE_VERSION(OpenSSLVersion.major, OpenSSLVersion.minor,
                         OpenSSLVersion.patch, OpenSSLVersion.build);

bool OPENSSL_VERSION_AT_LEAST()(int major, int minor, int patch = 0, int build = 0)
{
    return OPENSSL_VERSION_NUMBER >= OPENSSL_MAKE_VERSION(major, minor, patch, build);
}

bool OPENSSL_VERSION_BEFORE()(int major, int minor, int patch = 0, int build = 0)
{
    return OPENSSL_VERSION_NUMBER < OPENSSL_MAKE_VERSION(major, minor, patch, build);
}

/* The macros below are to be used for shared library (.so, .dll, ...)
 * versioning.  That kind of versioning works a bit differently between
 * operating systems.  The most usual scheme is to set a major and a minor
 * number, and have the runtime loader check that the major number is equal
 * to what it was at application link time, while the minor number has to
 * be greater or equal to what it was at application link time.  With this
 * scheme, the version number is usually part of the file name, like this:
 *
 *	libcrypto.so.0.9
 *
 * Some unixen also make a softlink with the major version number only:
 *
 *	libcrypto.so.0
 *
 * On Tru64 and IRIX 6.x it works a little bit differently.  There, the
 * shared library version is stored in the file, and is actually a series
 * of versions, separated by colons.  The rightmost version present in the
 * library when linking an application is stored in the application to be
 * matched at run time.  When the application is run, a check is done to
 * see if the library version stored in the application matches any of the
 * versions in the version string of the library itself.
 * This version string can be constructed in any way, depending on what
 * kind of matching is desired.  However, to implement the same scheme as
 * the one used in the other unixen, all compatible versions, from lowest
 * to highest, should be part of the string.  Consecutive builds would
 * give the following versions strings:
 *
 *	3.0
 *	3.0:3.1
 *	3.0:3.1:3.2
 *	4.0
 *	4.0:4.1
 *
 * Notice how version 4 is completely incompatible with version, and
 * therefore give the breach you can see.
 *
 * There may be other schemes as well that I haven't yet discovered.
 *
 * So, here's the way it works here: first of all, the library version
 * number doesn't need at all to match the overall OpenSSL version.
 * However, it's nice and more understandable if it actually does.
 * The current library version is stored in the macro SHLIB_VERSION_NUMBER,
 * which is just a piece of text in the format "M.m.e" (Major, minor, edit).
 * For the sake of Tru64, IRIX, and any other OS that behaves in similar ways,
 * we need to keep a history of version numbers, which is done in the
 * macro SHLIB_VERSION_HISTORY.  The numbers are separated by colons and
 * should only keep the versions that are binary compatible with the current.
 */
enum SHLIB_VERSION_HISTORY = "";
enum SHLIB_VERSION_NUMBER = "1.0.0";
