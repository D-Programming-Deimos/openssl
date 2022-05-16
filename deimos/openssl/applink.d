/**
 * Glue between OpenSSL BIO and Win32 compiler run-time
 *
 * Duplicate the content of the `applink.c` source file
 * to avoid linking it in user code without adding a dependency
 * to a C build system/compiler.
 *
 * See_Also: https://www.openssl.org/docs/manmaster/man3/OPENSSL_Applink.html
 */
module deimos.openssl.applink;

import core.stdc.stdio;
import std.stdio : _fileno, _setmode, _O_BINARY;
import core.sys.posix.fcntl;
import core.sys.posix.unistd;
import core.stdc.stdio;

enum APPLINK_STDIN	=1;
enum APPLINK_STDOUT	=2;
enum APPLINK_STDERR	=3;
enum APPLINK_FPRINTF	=4;
enum APPLINK_FGETS	=5;
enum APPLINK_FREAD	=6;
enum APPLINK_FWRITE	=7;
enum APPLINK_FSETMOD	=8;
enum APPLINK_FEOF	=9;
enum APPLINK_FCLOSE 	=10;	/* should not be used */

enum APPLINK_FOPEN	=11;	/* solely for completeness */
enum APPLINK_FSEEK	=12;
enum APPLINK_FTELL	=13;
enum APPLINK_FFLUSH	=14;
enum APPLINK_FERROR	=15;
enum APPLINK_CLEARERR =16;
enum APPLINK_FILENO	=17;	/* to be used with below */

enum APPLINK_OPEN	=18;	/* formally can't be used, as flags can vary */
enum APPLINK_READ	=19;
enum APPLINK_WRITE	=20;
enum APPLINK_LSEEK	=21;
enum APPLINK_CLOSE	=22;
enum APPLINK_MAX	=22;	/* always same as last macro */

enum _O_TEXT = 0x4000;

extern(C)
{
	void *app_stdin()		
	{ 
		return cast(void*)stdin;  
	}
	
	void *app_stdout()		
	{ 
		return cast(void*)stdout; 
	}
	
	void *app_stderr()		
	{ 
		return cast(void*)stderr; 
	}
	
	int app_feof(FILE *fp)		
	{ 
		return feof(fp); 
	}
	
	int app_ferror(FILE *fp)	
	{ 
		return ferror(fp); 
	}
	
	void app_clearerr(FILE *fp)
	{ 
		clearerr(fp); 
	}
	
	int app_fileno(FILE *fp)	
	{ 
		return _fileno(fp); 
	}
	
	int app_fsetmod(FILE *fp, char mod)
	{ 
		return _setmode (_fileno(fp),mod=='b'?_O_BINARY:_O_TEXT); 
	}
	
	__gshared bool once = true;
	__gshared void*[APPLINK_MAX+1] OPENSSL_ApplinkTable = cast(void*)APPLINK_MAX;
	
	export void** OPENSSL_Applink()
	{ 
		if (once)
		{	
			OPENSSL_ApplinkTable[APPLINK_STDIN]		= &app_stdin;
			OPENSSL_ApplinkTable[APPLINK_STDOUT]	= &app_stdout;
			OPENSSL_ApplinkTable[APPLINK_STDERR]	= &app_stderr;
			OPENSSL_ApplinkTable[APPLINK_FPRINTF]	= &fprintf;
			OPENSSL_ApplinkTable[APPLINK_FGETS]		= &fgets;
			OPENSSL_ApplinkTable[APPLINK_FREAD]		= &fread;
			OPENSSL_ApplinkTable[APPLINK_FWRITE]	= &fwrite;
			OPENSSL_ApplinkTable[APPLINK_FSETMOD]	= &app_fsetmod;
			OPENSSL_ApplinkTable[APPLINK_FEOF]		= &app_feof;
			OPENSSL_ApplinkTable[APPLINK_FCLOSE]	= &fclose;
			
			OPENSSL_ApplinkTable[APPLINK_FOPEN]		= &fopen;
			OPENSSL_ApplinkTable[APPLINK_FSEEK]		= &fseek;
			OPENSSL_ApplinkTable[APPLINK_FTELL]		= &ftell;
			OPENSSL_ApplinkTable[APPLINK_FFLUSH]	= &fflush;
			OPENSSL_ApplinkTable[APPLINK_FERROR]	= &app_ferror;
			OPENSSL_ApplinkTable[APPLINK_CLEARERR]	= &app_clearerr;
			OPENSSL_ApplinkTable[APPLINK_FILENO]	= &app_fileno;
			
			OPENSSL_ApplinkTable[APPLINK_OPEN]		= &fopen;
			OPENSSL_ApplinkTable[APPLINK_READ]		= &fread;
			OPENSSL_ApplinkTable[APPLINK_WRITE]		= &fwrite;
			OPENSSL_ApplinkTable[APPLINK_LSEEK]		= &fseek;
			OPENSSL_ApplinkTable[APPLINK_CLOSE]		= &fclose;
			
			once = false;
		}
		
		return OPENSSL_ApplinkTable.ptr;
	}
}