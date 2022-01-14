//
//  HTOpenSSL.c
//  HTOpenSSL
//
//  Created by hublot on 2018/2/8.
//

#import "HTOpenSSL.h"
#import <string.h>

#import <openssl/rsa.h>
#import <openssl/pem.h>
#import <openssl/bn.h>
#import <openssl/pkcs12.h>
#import <openssl/rand.h>
#import <openssl/x509v3.h>

X509 *crtobjectFrom(data_st data);

EVP_PKEY *keyobjectFrom(data_st data);

EVP_PKEY *creatersakey(unsigned int length);

X509_REQ *createreqWith(EVP_PKEY *key, char *host);

X509 *createsignWith(X509_REQ *req, X509 *cacrtobject, EVP_PKEY *cakeyobject, int year);

data_st pk12dataFrom(X509 *crtobject, EVP_PKEY *keyobject, char *password);



data_st createPK12With(char *host, data_st cacrtdata, data_st cakeydata, char *password) {
	X509 *cacrt = crtobjectFrom(cacrtdata);
	EVP_PKEY *cakey = keyobjectFrom(cakeydata);
	EVP_PKEY *key = creatersakey(2048);
	X509_REQ *req = createreqWith(key, host);
	X509 *crt = createsignWith(req, cacrt, cakey, 1);
	data_st pk12Data = pk12dataFrom(crt, key, password);
	X509_free(cacrt);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	X509_REQ_free(req);
	X509_free(crt);
	return pk12Data;
}

X509 *crtobjectFrom(data_st data) {
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, data.address, data.length);
	X509 *crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free_all(bio);
	return crt;
}

EVP_PKEY *keyobjectFrom(data_st data) {
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, data.address, data.length);
	EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free_all(bio);
	return key;
}

EVP_PKEY *creatersakey(unsigned int length) {
	EVP_PKEY *key = EVP_PKEY_new();
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();
	BN_set_word(e, 65537);
	RSA_generate_key_ex(rsa, length, e, NULL);
	EVP_PKEY_assign_RSA(key, rsa);
	BN_free(e);
	return key;
}

X509_REQ *createreqWith(EVP_PKEY *key, char *host) {
	X509_REQ *req = X509_REQ_new();
	X509_REQ_set_pubkey(req, key);
	X509_NAME *name = X509_REQ_get_subject_name(req);
	char *keylist[] = {"C", "ST", "L", "O", "OU", "CN"};
	char *valuelist[] = {"CN", "BJ", "BJ", "hoper", "hoper", host};
	for(int i = 0; i < sizeof(keylist) / sizeof(*keylist); i ++) {
		char *key = keylist[i];
		const unsigned char *value = (const unsigned char *)valuelist[i];
		X509_NAME_add_entry_by_txt(name, key, MBSTRING_ASC, value, - 1, - 1, 0);
	}
	
	STACK_OF(X509_EXTENSION) *extensionlist = sk_X509_EXTENSION_new_null();
	char *altKey = "subjectAltName";
	char *dnsKey = "DNS:";
	char *dnsValue = host;
	char *altValue = malloc(strlen(dnsKey) + strlen(dnsValue) + 1);
	strcat(altValue, dnsKey);
	strcat(altValue, dnsValue);
	X509_EXTENSION *extension = X509V3_EXT_conf(NULL, NULL, altKey, altValue);
	sk_X509_EXTENSION_push(extensionlist, extension);
	X509_REQ_add_extensions(req, extensionlist);
	sk_X509_EXTENSION_pop_free(extensionlist, X509_EXTENSION_free);
	X509_REQ_sign(req, key, EVP_sha256());
	free(altValue);
	return req;
}

X509 *createsignWith(X509_REQ *req, X509 *cacrtobject, EVP_PKEY *cakeyobject, int year) {
	X509 *crt = X509_new();
	X509_set_version(crt, 2);
	
	unsigned char serial_bytes[20];
	RAND_bytes(serial_bytes, sizeof(serial_bytes));
	serial_bytes[0] &= 0x7f;
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);
	X509_set_serialNumber(crt, serial);
	ASN1_INTEGER_free(serial);
	BN_free(bn);
	
	X509_set_issuer_name(crt, X509_get_subject_name(cacrtobject));
	
	X509_gmtime_adj(X509_getm_notBefore(crt), 0);
	X509_gmtime_adj(X509_getm_notAfter(crt), (long)365 * 24 * 3600 * year);
	X509_set_subject_name(crt, X509_REQ_get_subject_name(req));
	EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);
	
	STACK_OF(X509_EXTENSION) *extensionlist = X509_REQ_get_extensions(req);
	X509_EXTENSION *extension = sk_X509_EXTENSION_pop(extensionlist);
	X509_add_ext(crt, extension, - 1);
	
	X509_sign(crt, cakeyobject, EVP_sha256());
	X509_EXTENSION_free(extension);
	sk_X509_EXTENSION_free(extensionlist);
	return crt;
}

data_st pk12dataFrom(X509 *crtobject, EVP_PKEY *keyobject, char *password) {
	BIO *bio = BIO_new(BIO_s_mem());
	PKCS12 *pk12 = PKCS12_create(password, "hoper", keyobject, crtobject, NULL, 0, 0, 0, 0, 0);
	i2d_PKCS12_bio(bio, pk12);
	int size = BIO_pending(bio);
	void *byte = malloc(size + 1);
	BIO_read(bio, byte, size);
	PKCS12_free(pk12);
	BIO_free_all(bio);
	data_st data = {
		.address = byte,
		.length = size,
	};
	return data;
}
