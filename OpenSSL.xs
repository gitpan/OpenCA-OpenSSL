#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "const-c.inc"

/* Standard trick to have a C pointer as a Perl object, see the typemap */
typedef X509          * OpenCA_OpenSSL_X509;
typedef X509_CRL      * OpenCA_OpenSSL_CRL;
typedef NETSCAPE_SPKI * OpenCA_OpenSSL_SPKAC;
typedef X509_REQ      * OpenCA_OpenSSL_PKCS10;

MODULE = OpenCA::OpenSSL		PACKAGE = OpenCA::OpenSSL

INCLUDE: const-xs.inc

#########################################################################
MODULE = OpenCA::OpenSSL		PACKAGE = OpenCA::OpenSSL::X509

OpenCA_OpenSSL_X509
_new_from_der(SV * sv)
    PREINIT:
	unsigned char * dercert;
	SSize_t certlen;
    CODE:
	dercert = SvPV(sv, certlen);
	RETVAL = d2i_X509(NULL,&dercert,certlen);
    OUTPUT:
	RETVAL

OpenCA_OpenSSL_X509
_new_from_pem(SV * sv)
    PREINIT:
	unsigned char * pemcert;
	unsigned char * dercert;
	SSize_t certlen, inlen;
	char inbuf[512];
	BIO *bio_in, *bio_out, *b64;
    CODE:
	pemcert = SvPV(sv, certlen);
	bio_in  = BIO_new(BIO_s_mem());
	bio_out = BIO_new(BIO_s_mem());
	b64     = BIO_new(BIO_f_base64());

	/* load encoded data into bio_in */
	BIO_write(bio_in, pemcert+27, certlen-27-25);

	/* decode data from one bio into another one */
	BIO_push(b64, bio_in);
        while((inlen = BIO_read(b64, inbuf, 512)) > 0)
		BIO_write(bio_out, inbuf, inlen);

	/* create dercert */
	certlen = BIO_get_mem_data(bio_out, &dercert);

	/* create cert */
	RETVAL = d2i_X509(NULL,&dercert,certlen);
	BIO_free_all(bio_in);
	BIO_free_all(bio_out);
    OUTPUT:
	RETVAL

# We do not really support serials that don't fit in one int

int
serial(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	char * stringval;
    CODE:
	stringval = i2s_ASN1_INTEGER(NULL,X509_get_serialNumber(cert));
	RETVAL = atoi(stringval);
	free(stringval);
    OUTPUT:
	RETVAL

char *
subject(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *subject, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(out, X509_get_subject_name(cert), 0, XN_FLAG_RFC2253);
	n = BIO_get_mem_data(out, &subject);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, subject, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
issuer(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *issuer, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(out, X509_get_issuer_name(cert), 0, XN_FLAG_RFC2253);
	n = BIO_get_mem_data(out, &issuer);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, issuer, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
notBefore(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	unsigned char *not, *result;
	int n;
	BIO *out;
    CODE:
	out = BIO_new(BIO_s_mem());
	ASN1_TIME_print(out, X509_get_notBefore(cert));
	n = BIO_get_mem_data(out, &not);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, not, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
notAfter(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	unsigned char *not, *result;
	int n;
	BIO *out;
    CODE:
	out = BIO_new(BIO_s_mem());
	ASN1_TIME_print(out, X509_get_notAfter(cert));
	n = BIO_get_mem_data(out, &not);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, not, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
alias(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
    CODE:
	RETVAL = X509_alias_get0(cert, NULL);
    OUTPUT:
	RETVAL

char *
fingerprint (cert, digest_name="sha1")
	OpenCA_OpenSSL_X509 cert
	char *digest_name
    PREINIT:
	BIO *out;
	int j;
	unsigned int n;
	const EVP_MD *digest;
	unsigned char * fingerprint, *result;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned char str[3];
    CODE:
	out = BIO_new(BIO_s_mem());
	if (!strcmp ("sha1", digest_name))
		digest = EVP_sha1();
	else
		digest = EVP_md5();
	if (X509_digest(cert,digest,md,&n))
	{
		BIO_printf(out, "%s:", OBJ_nid2sn(EVP_MD_type(digest)));
		for (j=0; j<(int)n; j++)
		{
			BIO_printf (out, "%02X",md[j]);
			if (j+1 != (int)n) BIO_printf(out,":");
		}
	}
	n = BIO_get_mem_data(out, &fingerprint);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, fingerprint, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

unsigned long
subject_hash(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
    CODE:
	RETVAL = X509_subject_name_hash(cert);
    OUTPUT:
	RETVAL

char *
emailaddress (cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	int j, n;
        STACK *emlst;
	BIO *out;
	unsigned char *emails, *result;
    CODE:
	out = BIO_new(BIO_s_mem());
	emlst = X509_get1_email(cert);
	for (j = 0; j < sk_num(emlst); j++)
	{
		BIO_printf(out, "%s", sk_value(emlst, j));
		if (j+1 != (int)sk_num(emlst))
			BIO_printf(out,"\n");
	}
	X509_email_free(emlst);
	n = BIO_get_mem_data(out, &emails);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, emails, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
version(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *version, *result;
	unsigned char buf[1024];
	long l;
    CODE:
	out = BIO_new(BIO_s_mem());
	l = X509_get_version(cert);
	BIO_printf (out,"%lu (0x%lx)",l+1,l);
	l = BIO_get_mem_data(out, &version);
	result = (char *) malloc (l+1);
	result[l] = '\0';
	memcpy (result, version, l);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
pubkey_algorithm(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *pubkey, *result;
	X509_CINF *ci;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	ci = cert->cert_info;
	i2a_ASN1_OBJECT(out, ci->key->algor->algorithm);
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result[n] = '\0';
	memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
pubkey(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char *pubkey, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_get_pubkey(cert);
	if (pkey != NULL)
	{
		if (pkey->type == EVP_PKEY_RSA)
			RSA_print(out,pkey->pkey.rsa,0);
		else if (pkey->type == EVP_PKEY_DSA)
			DSA_print(out,pkey->pkey.dsa,0);
		EVP_PKEY_free(pkey);
	}
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result[n] = '\0';
	memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
keysize (cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char * pubkey, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_get_pubkey(cert);
	if (pkey != NULL)
	{
		if (pkey->type == EVP_PKEY_RSA)
			BIO_printf(out,"%d", BN_num_bits(pkey->pkey.rsa->n));
		EVP_PKEY_free(pkey);
	}
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
modulus (cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	unsigned char * modulus, *result;
	BIO *out;
	EVP_PKEY *pkey;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_get_pubkey(cert);
	if (pkey == NULL)
		BIO_printf(out,"");
	else if (pkey->type == EVP_PKEY_RSA)
		BN_print(out,pkey->pkey.rsa->n);
	else if (pkey->type == EVP_PKEY_DSA)
		BN_print(out,pkey->pkey.dsa->pub_key);
	else
		BIO_printf(out,"");
	EVP_PKEY_free(pkey);
	n = BIO_get_mem_data(out, &modulus);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, modulus, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
exponent (cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char *exponent, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_get_pubkey(cert);
	if (pkey == NULL)
		BIO_printf(out,"");
	else if (pkey->type == EVP_PKEY_RSA)
		BN_print(out,pkey->pkey.rsa->e);
	else if (pkey->type == EVP_PKEY_DSA)
		BN_print(out,pkey->pkey.dsa->pub_key);
	else
		BIO_printf(out,"");
	EVP_PKEY_free(pkey);
	n = BIO_get_mem_data(out, &exponent);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, exponent, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
extensions(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *ext, *result;
	X509_CINF *ci;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	ci = cert->cert_info;
	result = NULL;
	// there is a bug in X509V3_extensions_print
	// the causes the function to fail if title == NULL and indent == 0
	X509V3_extensions_print(out, NULL, ci->extensions, 0, 4);
	n = BIO_get_mem_data(out, &ext);
	if (n)
	{
		result = (char *) malloc (n+1);
		result [n] = '\0';
		memcpy (result, ext, n);
	}
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature_algorithm(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *sig, *result;
	X509_CINF *ci;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	ci = cert->cert_info;
	i2a_ASN1_OBJECT(out, ci->signature->algorithm);
	n = BIO_get_mem_data(out, &sig);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, sig, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature(cert)
	OpenCA_OpenSSL_X509 cert
    PREINIT:
	BIO *out;
	unsigned char *sig, *result;
	int n,i;
	unsigned char *s;
    CODE:
	out = BIO_new(BIO_s_mem());
	n=cert->signature->length;
	s=cert->signature->data;
	for (i=0; i<n; i++)
	{
		if ( ((i%18) == 0) && (i!=0) ) BIO_printf(out,"\n");
		BIO_printf(out,"%02x%s",s[i], (((i+1)%18) == 0)?"":":");
	}
	n = BIO_get_mem_data(out, &sig);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, sig, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

#########################################################################
MODULE = OpenCA::OpenSSL		PACKAGE = OpenCA::OpenSSL::CRL

OpenCA_OpenSSL_CRL
_new_from_der(SV * sv)
    PREINIT:
	unsigned char * dercrl;
	SSize_t crllen;
    CODE:
	dercrl = SvPV(sv, crllen);
	RETVAL = d2i_X509_CRL(NULL,&dercrl,crllen);
    OUTPUT:
	RETVAL

OpenCA_OpenSSL_CRL
_new_from_pem(SV * sv)
    PREINIT:
	unsigned char * pemcrl;
	unsigned char * dercrl;
	SSize_t crllen, inlen;
	char inbuf[512];
	BIO *bio_in, *bio_out, *b64;
	X509_CRL *crl;
    CODE:
	pemcrl = SvPV(sv, crllen);
	bio_in  = BIO_new(BIO_s_mem());
	bio_out = BIO_new(BIO_s_mem());
	b64     = BIO_new(BIO_f_base64());

	/* load encoded data into bio_in */
	BIO_write(bio_in, pemcrl+25, crllen-25-23);

	/* decode data from one bio into another one */
	BIO_push(b64, bio_in);
        while((inlen = BIO_read(b64, inbuf, 512)) > 0)
		BIO_write(bio_out, inbuf, inlen);

	/* create dercert */
	crllen = BIO_get_mem_data(bio_out, &dercrl);

	/* create cert */
	crl = d2i_X509_CRL(NULL,&dercrl,crllen);
	RETVAL = crl;
	BIO_free_all(bio_in);
	BIO_free_all(bio_out);
    OUTPUT:
	RETVAL

char *
version(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	BIO *out;
	unsigned char *version, *result;
	unsigned char buf[1024];
	long l;
    CODE:
	out = BIO_new(BIO_s_mem());
	l = X509_CRL_get_version(crl);
	BIO_printf (out,"%lu (0x%lx)",l+1,l);
	l = BIO_get_mem_data(out, &version);
	result = (char *) malloc (l+1);
	result[l] = '\0';
	memcpy (result, version, l);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
issuer(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	BIO *out;
	unsigned char *issuer, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(out, X509_CRL_get_issuer(crl), 0, XN_FLAG_RFC2253);
	n = BIO_get_mem_data(out, &issuer);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, issuer, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

unsigned long
issuer_hash(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
    CODE:
	RETVAL = X509_NAME_hash(X509_CRL_get_issuer(crl));
    OUTPUT:
	RETVAL

char *
lastUpdate(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	unsigned char *not, *result;
	int n;
	BIO *out;
    CODE:
	out = BIO_new(BIO_s_mem());
	ASN1_TIME_print(out, X509_CRL_get_lastUpdate(crl));
	n = BIO_get_mem_data(out, &not);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, not, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
nextUpdate(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	unsigned char *not, *result;
	int n;
	BIO *out;
    CODE:
	out = BIO_new(BIO_s_mem());
	ASN1_TIME_print(out, X509_CRL_get_nextUpdate(crl));
	n = BIO_get_mem_data(out, &not);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, not, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
fingerprint (crl, digest_name="sha1")
	OpenCA_OpenSSL_CRL crl
	char *digest_name
    PREINIT:
	BIO *out;
	int j;
	unsigned int n;
	const EVP_MD *digest;
	unsigned char * fingerprint, *result;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned char str[3];
    CODE:
	out = BIO_new(BIO_s_mem());
	if (!strcmp ("sha1", digest_name))
		digest = EVP_sha1();
	else
		digest = EVP_md5();
	if (X509_CRL_digest(crl,digest,md,&n))
	{
		BIO_printf(out, "%s:", OBJ_nid2sn(EVP_MD_type(digest)));
		for (j=0; j<(int)n; j++)
		{
			BIO_printf (out, "%02X",md[j]);
			if (j+1 != (int)n) BIO_printf(out,":");
		}
	}
	n = BIO_get_mem_data(out, &fingerprint);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, fingerprint, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature_algorithm(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	BIO *out;
	unsigned char *sig, *result;
	X509_CINF *ci;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(out, crl->sig_alg->algorithm);
	n = BIO_get_mem_data(out, &sig);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, sig, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	BIO *out;
	unsigned char *sig, *result;
	int n,i;
	unsigned char *s;
    CODE:
	out = BIO_new(BIO_s_mem());
	n=crl->signature->length;
	s=crl->signature->data;
	for (i=0; i<n; i++)
	{
		if ( ((i%18) == 0) && (i!=0) ) BIO_printf(out,"\n");
		BIO_printf(out,"%02x%s",s[i], (((i+1)%18) == 0)?"":":");
	}
	n = BIO_get_mem_data(out, &sig);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, sig, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
extensions(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	BIO *out;
	unsigned char *ext, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	result = NULL;
	// there is a bug in X509V3_extensions_print
	// the causes the function to fail if title == NULL and indent == 0
	X509V3_extensions_print(out, NULL, crl->crl->extensions, 0, 4);
	n = BIO_get_mem_data(out, &ext);
	if (n)
	{
		result = (char *) malloc (n+1);
		result [n] = '\0';
		memcpy (result, ext, n);
	}
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
revoked(crl)
	OpenCA_OpenSSL_CRL crl
    PREINIT:
	BIO *out;
	unsigned char *ext, *result;
	int n,i;
	STACK_OF(X509_REVOKED) *rev;
	X509_REVOKED *r;
    CODE:
	out = BIO_new(BIO_s_mem());
	result = NULL;
	// there is a bug in X509V3_extensions_print
	// the causes the function to fail if title == NULL and indent == 0

	rev = X509_CRL_get_REVOKED(crl);

	for(i = 0; i < sk_X509_REVOKED_num(rev); i++) {
		r = sk_X509_REVOKED_value(rev, i);
		i2a_ASN1_INTEGER(out,r->serialNumber);
		BIO_printf(out,"\n        ");
		ASN1_TIME_print(out,r->revocationDate);
		BIO_printf(out,"\n");
		X509V3_extensions_print(out, NULL,
			r->extensions, 0, 8);
	}
	n = BIO_get_mem_data(out, &ext);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, ext, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

#########################################################################
MODULE = OpenCA::OpenSSL		PACKAGE = OpenCA::OpenSSL::SPKAC

OpenCA_OpenSSL_SPKAC
_new(SV * sv)
    PREINIT:
	unsigned char * spkac;
	SSize_t len;
	BIO *bio;
	CONF *conf = NULL;
	int i;
	char *spkstr = NULL;
    CODE:
	spkac = SvPV(sv, len);

	bio  = BIO_new(BIO_s_mem());

	/* load encoded data into bio */
	BIO_write(bio, spkac, len);

        conf = NCONF_new(NULL);
        i = NCONF_load_bio(conf, bio, NULL);

        if(!i) {
		exit (100);
        }

        spkstr = NCONF_get_string(conf, "default", "SPKAC");

	/* RETVAL = NETSCAPE_SPKI_b64_decode(spkac, len); */
	RETVAL = NETSCAPE_SPKI_b64_decode(spkstr, -1);
    OUTPUT:
	RETVAL

char *
pubkey_algorithm(spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	BIO *out;
	unsigned char *pubkey, *result;
	X509_CINF *ci;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(out, spkac->spkac->pubkey->algor->algorithm);
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result[n] = '\0';
	memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
pubkey(spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char *pubkey, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_PUBKEY_get(spkac->spkac->pubkey);
	if (pkey != NULL)
	{
		if (pkey->type == EVP_PKEY_RSA)
			RSA_print(out,pkey->pkey.rsa,0);
		else if (pkey->type == EVP_PKEY_DSA)
			DSA_print(out,pkey->pkey.dsa,0);
		EVP_PKEY_free(pkey);
	}
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result[n] = '\0';
	memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
keysize (spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char * pubkey, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_PUBKEY_get(spkac->spkac->pubkey);
	if (pkey != NULL)
	{
		if (pkey->type == EVP_PKEY_RSA)
			BIO_printf(out,"%d", BN_num_bits(pkey->pkey.rsa->n));
		EVP_PKEY_free(pkey);
	}
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
modulus (spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	unsigned char * modulus, *result;
	BIO *out;
	EVP_PKEY *pkey;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_PUBKEY_get(spkac->spkac->pubkey);
	if (pkey == NULL)
		BIO_printf(out,"");
	else if (pkey->type == EVP_PKEY_RSA)
		BN_print(out,pkey->pkey.rsa->n);
	else if (pkey->type == EVP_PKEY_DSA)
		BN_print(out,pkey->pkey.dsa->pub_key);
	else
		BIO_printf(out,"");
	EVP_PKEY_free(pkey);
	n = BIO_get_mem_data(out, &modulus);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, modulus, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
exponent (spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char *exponent, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_PUBKEY_get(spkac->spkac->pubkey);
	if (pkey == NULL)
		BIO_printf(out,"");
	else if (pkey->type == EVP_PKEY_RSA)
		BN_print(out,pkey->pkey.rsa->e);
	else if (pkey->type == EVP_PKEY_DSA)
		BN_print(out,pkey->pkey.dsa->pub_key);
	else
		BIO_printf(out,"");
	EVP_PKEY_free(pkey);
	n = BIO_get_mem_data(out, &exponent);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, exponent, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature_algorithm(spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	unsigned char *result;
    CODE:
	result = (char *) malloc (1);
	result [0] = '\0';
	RETVAL = result;
    OUTPUT:
	RETVAL

char *
signature(spkac)
	OpenCA_OpenSSL_SPKAC spkac
    PREINIT:
	unsigned char *result;
    CODE:
	result = (char *) malloc (1);
	result [0] = '\0';
	RETVAL = result;
    OUTPUT:
	RETVAL

#########################################################################
MODULE = OpenCA::OpenSSL		PACKAGE = OpenCA::OpenSSL::PKCS10

OpenCA_OpenSSL_PKCS10
_new_from_der(SV * sv)
    PREINIT:
	unsigned char * dercsr;
	SSize_t csrlen;
    CODE:
	dercsr = SvPV(sv, csrlen);
	RETVAL = d2i_X509_REQ(NULL,&dercsr,csrlen);
    OUTPUT:
	RETVAL

OpenCA_OpenSSL_PKCS10
_new_from_pem(SV * sv)
    PREINIT:
	unsigned char * pemcsr;
	unsigned char * dercsr;
	SSize_t csrlen, inlen;
	char inbuf[512];
	BIO *bio_in, *bio_out, *b64;
    CODE:
	pemcsr  = SvPV(sv, csrlen);
	bio_in  = BIO_new(BIO_s_mem());
	bio_out = BIO_new(BIO_s_mem());
	b64     = BIO_new(BIO_f_base64());

	/* load encoded data into bio_in */
	BIO_write(bio_in, pemcsr+36, csrlen-36-34);

	/* decode data from one bio into another one */
	BIO_push(b64, bio_in);
        while((inlen = BIO_read(b64, inbuf, 512)) > 0)
		BIO_write(bio_out, inbuf, inlen);

	/* create dercsr */
	csrlen = BIO_get_mem_data(bio_out, &dercsr);

	/* create csr */
	RETVAL = d2i_X509_REQ(NULL,&dercsr,csrlen);
	BIO_free_all(bio_in);
	BIO_free_all(bio_out);
    OUTPUT:
	RETVAL

# We do not really support serials that don't fit in one int

char *
version(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *version, *result;
	unsigned char buf[1024];
	long l, i;
	const char *neg;
    CODE:
	out = BIO_new(BIO_s_mem());

	neg=(csr->req_info->version->type == V_ASN1_NEG_INTEGER)?"-":"";
	l=0;
	for (i=0; i<csr->req_info->version->length; i++)
		{ l<<=8; l+=csr->req_info->version->data[i]; }
	/* why we use l and not l+1 like for all other versions? */
	BIO_printf(out,"%s%lu (%s0x%lx)",neg,l,neg,l);
	l = BIO_get_mem_data(out, &version);
	result = (char *) malloc (l+1);
	result[l] = '\0';
	memcpy (result, version, l);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
subject(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *subject, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(out, csr->req_info->subject, 0, XN_FLAG_RFC2253);
	n = BIO_get_mem_data(out, &subject);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, subject, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

unsigned long
subject_hash(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
    CODE:
	RETVAL = X509_NAME_hash(csr->req_info->subject);
    OUTPUT:
	RETVAL

char *
fingerprint (csr, digest_name="sha1")
	OpenCA_OpenSSL_PKCS10 csr
	char *digest_name
    PREINIT:
	BIO *out;
	int j;
	unsigned int n;
	const EVP_MD *digest;
	unsigned char * fingerprint, *result;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned char str[3];
    CODE:
	out = BIO_new(BIO_s_mem());
	if (!strcmp ("sha1", digest_name))
		digest = EVP_sha1();
	else
		digest = EVP_md5();
	if (X509_REQ_digest(csr,digest,md,&n))
	{
		BIO_printf(out, "%s:", OBJ_nid2sn(EVP_MD_type(digest)));
		for (j=0; j<(int)n; j++)
		{
			BIO_printf (out, "%02X",md[j]);
			if (j+1 != (int)n) BIO_printf(out,":");
		}
	}
	n = BIO_get_mem_data(out, &fingerprint);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, fingerprint, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
emailaddress (csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	int j, n;
        STACK *emlst;
	BIO *out;
	unsigned char *emails, *result;
    CODE:
	out = BIO_new(BIO_s_mem());
	emlst = X509_REQ_get1_email(csr);
	for (j = 0; j < sk_num(emlst); j++)
	{
		BIO_printf(out, "%s", sk_value(emlst, j));
		if (j+1 != (int)sk_num(emlst))
			BIO_printf(out,"\n");
	}
	X509_email_free(emlst);
	n = BIO_get_mem_data(out, &emails);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, emails, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
pubkey_algorithm(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *pubkey, *result;
	X509_REQ_INFO *ri;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	ri = csr->req_info;
	i2a_ASN1_OBJECT(out, ri->pubkey->algor->algorithm);
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result[n] = '\0';
	memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
pubkey(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char *pubkey, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_REQ_get_pubkey(csr);
	if (pkey != NULL)
	{
		if (pkey->type == EVP_PKEY_RSA)
			RSA_print(out,pkey->pkey.rsa,0);
		else if (pkey->type == EVP_PKEY_DSA)
			DSA_print(out,pkey->pkey.dsa,0);
		EVP_PKEY_free(pkey);
	}
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result[n] = '\0';
	memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
keysize (csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char * pubkey, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_REQ_get_pubkey(csr);
	if (pkey != NULL)
	{
		if (pkey->type == EVP_PKEY_RSA)
			BIO_printf(out,"%d", BN_num_bits(pkey->pkey.rsa->n));
		EVP_PKEY_free(pkey);
	}
	n = BIO_get_mem_data(out, &pubkey);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, pubkey, n);
	RETVAL = strdup (result);
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
modulus (csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	unsigned char * modulus, *result;
	BIO *out;
	EVP_PKEY *pkey;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_REQ_get_pubkey(csr);
	if (pkey == NULL)
		BIO_printf(out,"");
	else if (pkey->type == EVP_PKEY_RSA)
		BN_print(out,pkey->pkey.rsa->n);
	else if (pkey->type == EVP_PKEY_DSA)
		BN_print(out,pkey->pkey.dsa->pub_key);
	else
		BIO_printf(out,"");
	EVP_PKEY_free(pkey);
	n = BIO_get_mem_data(out, &modulus);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, modulus, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
exponent (csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	EVP_PKEY *pkey;
	unsigned char *exponent, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	pkey=X509_REQ_get_pubkey(csr);
	if (pkey == NULL)
		BIO_printf(out,"");
	else if (pkey->type == EVP_PKEY_RSA)
		BN_print(out,pkey->pkey.rsa->e);
	else if (pkey->type == EVP_PKEY_DSA)
		BN_print(out,pkey->pkey.dsa->pub_key);
	else
		BIO_printf(out,"");
	EVP_PKEY_free(pkey);
	n = BIO_get_mem_data(out, &exponent);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, exponent, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
extensions(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *ext, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	result = NULL;
	// there is a bug in X509V3_extensions_print
	// the causes the function to fail if title == NULL and indent == 0
	X509V3_extensions_print(out, NULL, X509_REQ_get_extensions(csr), 0, 4);
	n = BIO_get_mem_data(out, &ext);
	if (n)
	{
		result = (char *) malloc (n+1);
		result [n] = '\0';
		memcpy (result, ext, n);
	}
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
attributes(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *ext, *result;
	STACK_OF(X509_ATTRIBUTE) *sk;
	int n,i;
    CODE:
	out = BIO_new(BIO_s_mem());
	result = NULL;
	sk=csr->req_info->attributes;
	for (i=0; i<sk_X509_ATTRIBUTE_num(sk); i++)
	{
		ASN1_TYPE *at;
		X509_ATTRIBUTE *a;
		ASN1_BIT_STRING *bs=NULL;
		ASN1_TYPE *t;
		int j,type=0,count=1,ii=0;
	
		a=sk_X509_ATTRIBUTE_value(sk,i);
		if(X509_REQ_extension_nid(OBJ_obj2nid(a->object)))
			continue;
		if ((j=i2a_ASN1_OBJECT(out,a->object)) > 0)
		{
			if (a->single)
			{
				t=a->value.single;
				type=t->type;
				bs=t->value.bit_string;
			}
			else
			{
				ii=0;
				count=sk_ASN1_TYPE_num(a->value.set);
get_next:
				at=sk_ASN1_TYPE_value(a->value.set,ii);
				type=at->type;
				bs=at->value.asn1_string;
			}
		}
		for (j=25-j; j>0; j--)
			BIO_write(out," ",1);
		BIO_puts(out,":");
		if (    (type == V_ASN1_PRINTABLESTRING) ||
			(type == V_ASN1_T61STRING) ||
			(type == V_ASN1_IA5STRING))
		{
			BIO_write(out,(char *)bs->data,bs->length);
			BIO_puts(out,"\n");
		}
		else
			BIO_puts(out,"unable to print attribute\n");
		if (++ii < count) goto get_next;
	}
	n = BIO_get_mem_data(out, &ext);
	if (n)
	{
		result = (char *) malloc (n+1);
		result [n] = '\0';
		memcpy (result, ext, n);
	}
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature_algorithm(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *sig, *result;
	int n;
    CODE:
	out = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(out, csr->sig_alg->algorithm);
	n = BIO_get_mem_data(out, &sig);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, sig, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL

char *
signature(csr)
	OpenCA_OpenSSL_PKCS10 csr
    PREINIT:
	BIO *out;
	unsigned char *sig, *result;
	int n,i;
	unsigned char *s;
    CODE:
	out = BIO_new(BIO_s_mem());
	n=csr->signature->length;
	s=csr->signature->data;
	for (i=0; i<n; i++)
	{
		if ( ((i%18) == 0) && (i!=0) ) BIO_printf(out,"\n");
		BIO_printf(out,"%02x%s",s[i], (((i+1)%18) == 0)?"":":");
	}
	n = BIO_get_mem_data(out, &sig);
	result = (char *) malloc (n+1);
	result [n] = '\0';
        memcpy (result, sig, n);
	RETVAL = result;
	BIO_free(out);
    OUTPUT:
	RETVAL
