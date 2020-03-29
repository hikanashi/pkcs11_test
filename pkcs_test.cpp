//#include "pch.h"
#include <stdio.h>
//#include <sys/eventfd.h>
#include <string>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/conf.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pkcs12.h>

#include <openssl/engine.h>
#include <openssl/ui.h>

#include <iostream>

#include "logout.h"


#ifdef _WIN32
#define strcat(str1,str2)		\
	do {						\
		strcat_s(str1, sizeof(str1), str2);	\
	} while (0);
#endif


#define LOGOUT_S(stream, ...)	LOGOUT(__VA_ARGS__)

#define USE_OPENSSL_ENGINE 

struct UrlState {
	/* void instead of ENGINE to avoid bleeding OpenSSL into this header */
	ENGINE* engine;
};

struct Curl_easy {
	struct UrlState state;       /* struct for fields used for state info and
									other dynamic purposes */
};

/* Return error string for last OpenSSL error
 */
static char * ossl_strerror(unsigned long error, char *buf, size_t size)
{
	ERR_error_string_n(error, buf, size);
	return buf;
}

static int Curl_ossl_init(void)
{
	OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN
		| OPENSSL_INIT_LOAD_CONFIG, NULL);

#if 0
	OPENSSL_load_builtin_modules();

#ifdef USE_OPENSSL_ENGINE
	ENGINE_load_builtin_engines();
#endif

#ifndef CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG
	CONF_modules_load_file(NULL, NULL,
		CONF_MFLAGS_DEFAULT_SECTION |
		CONF_MFLAGS_IGNORE_MISSING_FILE);
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && \
    !defined(LIBRESSL_VERSION_NUMBER)
	/* OpenSSL 1.1.0+ takes care of initialization itself */
#else
	/* Lets get nice error messages */
	SSL_load_error_strings();

	/* Init the global ciphers and digests */
	if (!SSLeay_add_ssl_algorithms())
		return 0;

	OpenSSL_add_all_algorithms();
#endif

#endif
	return 1;
}


static void Curl_ossl_cleanup(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && \
    !defined(LIBRESSL_VERSION_NUMBER)
	/* OpenSSL 1.1 deprecates all these cleanup functions and
	   turns them into no-ops in OpenSSL 1.0 compatibility mode */
#else
	/* Free ciphers and digests lists */
	EVP_cleanup();

#ifdef HAVE_ENGINE_CLEANUP
	/* Free engine list */
	ENGINE_cleanup();
#endif

	/* Free OpenSSL error strings */
	ERR_free_strings();

	/* Free thread local error state, destroying hash upon zero refcount */
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
	ERR_remove_thread_state(NULL);
#else
	ERR_remove_state(0);
#endif

	/* Free all memory allocated by all configuration modules */
	CONF_modules_free();

#ifdef HAVE_SSL_COMP_FREE_COMPRESSION_METHODS
	SSL_COMP_free_compression_methods();
#endif
#endif
}

static int Curl_ossl_set_engine(struct Curl_easy *data,
	const char *engine)
{
	ENGINE *e;

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
	e = ENGINE_by_id(engine);
#else
	/* avoid memory leak */
	for (e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
		const char *e_id = ENGINE_get_id(e);
		if (!strcmp(engine, e_id))
			break;
	}
#endif

	if (!e) {
		LOGOUT("SSL Engine '%s' not found", engine);
		return -1;
	}

	if (data->state.engine) {
		ENGINE_finish(data->state.engine);
		ENGINE_free(data->state.engine);
		data->state.engine = NULL;
	}
	if (!ENGINE_init(e)) {
		char buf[256];

		ENGINE_free(e);
		LOGOUT("Failed to initialise SSL Engine '%s':\n%s",
			engine, ossl_strerror(ERR_get_error(), buf, sizeof(buf)));
		return -2;
	}
	data->state.engine = e;
	return 0;
}


static
int cert_stuff(struct Curl_easy *data,
	const char *cert_file)
{
	char error_buffer[256];

	if (data->state.engine) {
		const char *cmd_name = "LOAD_CERT_CTRL";
		struct {
			const char *cert_id;
			X509 *cert;
		} params;

		params.cert_id = cert_file;
		params.cert = NULL;

		/* Does the engine supports LOAD_CERT_CTRL ? */
		if (!ENGINE_ctrl(data->state.engine, ENGINE_CTRL_GET_CMD_FROM_NAME,
			0, (void *)cmd_name, NULL)) {
			LOGOUT("ssl engine does not support loading certificates");
			return 0;
		}

		/* Load the certificate from the engine */
		if (!ENGINE_ctrl_cmd(data->state.engine, cmd_name,
			0, &params, NULL, 1)) {
			LOGOUT("ssl engine cannot load client cert with id"
				" '%s' [%s]", cert_file,
				ossl_strerror(ERR_get_error(), error_buffer,
					sizeof(error_buffer)));
			return 0;
		}

		if (!params.cert) {
			LOGOUT("ssl engine didn't initialized the certificate "
				"properly.");
			return 0;
		}

		BIO *certmem = BIO_new(BIO_s_mem());
		X509_print(certmem, params.cert);
		char* certout = NULL;
		long certsize = BIO_get_mem_data(certmem, &certout);
//		LOGOUT("size=%d\n", certsize);
		printf("%s", certout);
		BIO_free(certmem);


		BIO *pemmem = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(pemmem, params.cert);
		char* pemout = NULL;
		long pemsize = BIO_get_mem_data(pemmem, &pemout);
//		LOGOUT("size=%d\n", pemsize);
		printf("%s", pemout);
		BIO_free(pemmem);

		X509_free(params.cert); /* we don't need the handle any more... */
	}
	else {
		LOGOUT("crypto engine not set, can't load certificate");
		return 0;
	}

	return 1;
}



int main(int argc, char** argv)
{


//	set_pkcs11_path("aaaaa", "bbbbbb");
#ifdef _WIN32
	putenv("PKCS11_PRIVATEKEY=/opt/local/ssl/pc1key.pem");
	putenv("PKCS11_CLIENTCRT=/opt/local/ssl/pc1CA.pem");
#else
	putenv("PKCS11_PRIVATEKEY=/home/user/.local/ssl/pc1key.pem");
	putenv("PKCS11_CLIENTCRT=/home/user/.local/ssl/pc1CA.pem");
#endif

#if 0
	char curdir[1024 + 1] = { 0 };
//	getcwd(curdir, sizeof(curdir) - 1);
	strcpy(curdir, "C:\\opt\\local\\ssl");

	char confpath[1024 + 1] = { 0 };
#ifdef _WIN32
	snprintf(confpath, sizeof(confpath) - 1, "OPENSSL_CONF=%s\\openssl.cnf", curdir);
#else
	snprintf(confpath, sizeof(confpath)-1, "OPENSSL_CONF=%s/openssl.cnf", curdir);
#endif
	LOGOUT("### env %s\n", confpath);
	putenv(confpath);

	putenv("OPENSSL_ENGINES=/opt/local/lib/");


	char sslpath[1024 + 1] = { 0 };
	snprintf(sslpath, sizeof(sslpath) - 1, "OPENSSL_DIR=%s", curdir);


	const char* confenv = getenv("OPENSSL_CONF");
	LOGOUT("### get OPENSSL_CONF=%s\n", confenv ? confenv : "null");
#endif

	std::string certid;
	std::cout << "input certid:";
	std::cin >> certid;

	int ret = 0;
	ret = Curl_ossl_init();
	if (!ret)
	{
		LOGOUT("Curl_ossl_init fail.\n");
	}

	struct Curl_easy easy = { 0 };
	Curl_ossl_set_engine(&easy, "pkcs11");


	cert_stuff(&easy, certid.c_str());

	fflush(stdout);

	Curl_ossl_cleanup();

	return 0;
}

