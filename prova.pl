#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
my $openssl = new OpenCA::OpenSSL;

$openssl->setParams ( SHELL=>"/usr/local/ssl/bin/openssl",
		      CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf",
		      VERIFY=>"/usr/local/ssl/bin/verify",
		      SIGN=>"/usr/local/ssl/bin/sign" );

$openssl->setParams ( STDERR => "/dev/null" );

if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error";
}

$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
 		DN=>["madwolf\@openca.org", "Massimiliano Pala", "", "", "" ] );

$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>500,
			OUTFILE=>"cert.pem");

$k = $openssl->dataConvert( INFILE=>"cert.pem",
 			    DATATYPE=>CERTIFICATE,
 			    OUTFORM=>NET ); 
 
$k = $openssl->dataConvert( INFILE=>"req.pem",
			    DATATYPE=>REQ,
			    OUTFORM=>TXT ); 

## print "$k\n\n";

$crl = $openssl->issueCrl( CACERT=>"cert.pem", CAKEY=>"priv.key",
			   OUTFORM=>TXT, DAYS=>"500");

print "$crl\n";

print "CRL Digest ... \n";
print "    * MD5 : ";
print $openssl->getDigest( DATA=>$crl, ALGORITHM=>md5 ) . "\n";
print "    * SHA1 : ";
print $openssl->getDigest( DATA=>$crl, ALGORITHM=>sha1 ) . "\n";

print $openssl->verify( SIGNATURE_FILE=>"sig", CA_CERT=>"cert.pem",
			VERBOSE=>"1" );

exit 0; 

