#include <nspr.h>
#include <nss.h>
#include <secerr.h>
#include <sslerr.h>
#include <ssl.h>
#include <private/pprio.h>
#include <Windows.h>
#define TMP_BUFFER_SIZE 1024
#define NSS_Version "3.26"
#define HOSTNAME "216.58.212.163" //IP of google.de
#define PORT 443
#pragma comment(lib, "ws2_32.lib")
int err;

const char* SEND_MSG = "GET / HTTP/1.1\r\nHost: www.google.de\r\nConnection: close\r\n\r\n"; //Get Request for google main page
const char* SECU_ErrorString(int err) {
	switch (err) {
	case 0: return "No error";
	case SEC_ERROR_BAD_DATA: return "Bad data";
	case SEC_ERROR_BAD_DATABASE: return "Problem with database";
	case SEC_ERROR_BAD_DER: return "Problem with DER";
	case SEC_ERROR_BAD_KEY: return "Problem with key";
	case SEC_ERROR_BAD_PASSWORD: return "Incorrect password";
	case SEC_ERROR_BAD_SIGNATURE: return "Bad signature";
	case SEC_ERROR_EXPIRED_CERTIFICATE: return "Expired certificate";
	case SEC_ERROR_INPUT_LEN: return "Problem with input length";
	case SEC_ERROR_INVALID_ALGORITHM: return "Invalid algorithm";
	case SEC_ERROR_INVALID_ARGS: return "Invalid arguments";
	case SEC_ERROR_INVALID_AVA: return "Invalid AVA";
	case SEC_ERROR_INVALID_TIME: return "Invalid time";
	case SEC_ERROR_IO: return "Security I/O error";
	case SEC_ERROR_LIBRARY_FAILURE: return "Library failure";
	case SEC_ERROR_NO_MEMORY: return "Out of memory";
	case SEC_ERROR_OLD_CRL: return "CRL is older than the current one";
	case SEC_ERROR_OUTPUT_LEN: return "Problem with output length";
	case SEC_ERROR_UNKNOWN_ISSUER: return "Unknown issuer";
	case SEC_ERROR_UNTRUSTED_CERT: return "Untrusted certificate";
	case SEC_ERROR_UNTRUSTED_ISSUER: return "Untrusted issuer";
	case SSL_ERROR_BAD_CERTIFICATE: return "Bad certificate";
	case SSL_ERROR_BAD_CLIENT: return "Bad client";
	case SSL_ERROR_BAD_SERVER: return "Bad server";
	case SSL_ERROR_EXPORT_ONLY_SERVER: return "Export only server";
	case SSL_ERROR_NO_CERTIFICATE: return "No certificate";
	case SSL_ERROR_NO_CYPHER_OVERLAP: return "No cypher overlap";
	case SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE: return "Unsupported certificate type";
	case SSL_ERROR_UNSUPPORTED_VERSION: return "Unsupported version";
	case SSL_ERROR_US_ONLY_SERVER: return "U.S. only server";
	case PR_IO_ERROR: return "I/O error";
	case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE: return "Expired Issuer Certificate";
	case SEC_ERROR_REVOKED_CERTIFICATE: return "Revoked certificate";
	case SEC_ERROR_NO_KEY: return "No private key in database for this cert";
	case SEC_ERROR_CERT_NOT_VALID: return "Certificate is not valid";
	case SEC_ERROR_EXTENSION_NOT_FOUND: return "Certificate extension was not found";
	case SEC_ERROR_EXTENSION_VALUE_INVALID: return "Certificate extension value invalid";
	case SEC_ERROR_CA_CERT_INVALID: return "Issuer certificate is invalid";
	case SEC_ERROR_CERT_USAGES_INVALID: return "Certificate usages is invalid";
	case SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION: return "Certificate has unknown critical extension";
	case SEC_ERROR_PKCS7_BAD_SIGNATURE: return "Bad PKCS7 signature";
	case SEC_ERROR_INADEQUATE_KEY_USAGE: return "Certificate not approved for this operation";
	case SEC_ERROR_INADEQUATE_CERT_TYPE: return "Certificate not approved for this operation";
	default: return "Unknown error";
	}
}
typedef struct NSS_Connection {
	PRFileDesc* tcpSocket, * sslSocket;
}NSS_Connection;

void NSS_cleanup();
void NSS_run();
void NSS_init();
void NSS_setup_and_connect(NSS_Connection* connection, const char* hostname, int port);
char* NSS_get_response(NSS_Connection* connection);
int tcp_connect(const char* hostname, int port);
SECStatus nss_auth_cert_hook(void* arg, PRFileDesc* fd, PRBool checksig, PRBool isServer);