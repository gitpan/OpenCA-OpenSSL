## OpenCA::OpenSSL
##
## Copyright (C) 1998-2001 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
## Contributions by:
##          Martin Leung <ccmartin@ust.hk>
##	    Uwe Gansert <ug@suse.de>

##
## General Errorcodes:
##
## The errorcodes consists of seven numbers:
## 1234567
## 12: module
## 34: function
## 567: errorcode
##
## The modules errorcode is 77.
##
## The functions use the following errorcodes:
##
## new			00
## setParams		01
## errno		02
## errval		03
## genKey		11
## genReq		12
## genCert		13
## crl2pkcs7		21
## dataConvert		22
## issueCert		31
## revoke		32
## issueCrl		33
## SPKAC		41
## getDigest		51
## verify		42
## sign			43
## getCertAttribute	61
## getReqAttribute	62
## getCRLAttribute	63
## pkcs7Certs		44
## updateDB		71
## getSMIME		52
## getPIN		53
## getOpenSSLDate	54
## getNumericDate	55
	

use strict;

package OpenCA::OpenSSL;

our ($errno, $errval);

use X500::DN;
use Carp;
use OpenCA::OpenSSL::SMIME;

($OpenCA::OpenSSL::VERSION = '$Revision: 1.91 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

## Global Variables Go HERE
my %params = (
	 shell => undef,
	 cnf => undef,
	 tmpDir => undef,
	 baseDir => undef,
	 verify => undef,
	 sign => undef,
	 errno => undef,
	 errval => undef
);

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

	my $keys = { @_ };

	$self->setParams( @_ );

	if( not $self->{binDir} ) {
		$self->{binDir} = "/usr/bin";
	};

        if( not $self->{shell} ) {
                $self->{shell} = "$self->{binDir}/openssl";
        };

	if( not $self->{verify} ) {
		$self->{verify} = "$self->{binDir}/openca-verify";
	};

	if( not $self->{sign} ) {
		$self->{sign} = "$self->{binDir}/openca-sign";
	};

	if( not $self->{tmpDir} ) {
		$self->{tmpDir} = '/tmp';
	};

	if( not -e "$self->{shell}" ) {
		return;
	};

	$self->setError (0, "");

        return $self;
}


sub setParams {

	my $self = shift;
	my $params = { @_ };
	my $key;

	foreach $key ( keys %{$params} ) {

		$self->{cnf}    = $params->{$key} if ( $key =~ /CONFIG/ );
		$self->{shell}  = $params->{$key} if ( $key =~ /SHELL/  );
		$self->{tmpDir} = $params->{$key} if ( $key =~ /TMPDIR/ );
		$self->{binDir} = $params->{$key} if ( $key =~ /BINDIR/ );
		$self->{verify} = $params->{$key} if ( $key =~ /VERIFY/ );
		$self->{sign}   = $params->{$key} if ( $key =~ /SIGN/ );
		$self->{DEBUG}  = $params->{$key} if ( $key =~ /DEBUG/ );
		open STDERR, $params->{$key} if ( $key =~ /STDERR/ );
		$self->{$key}   = $params->{$key};
	}

	return 1;
}

sub errno {
        my $self = shift;

        return $errno;
}

sub errval {
        my $self = shift;

        return $errval;
}

sub setError {
	my $self = shift;

	if (scalar (@_) == 4) {
		my $keys = { @_ };
		$errval	= $keys->{ERRVAL};
		$errno	= $keys->{ERRNO};
	} else {
		$errno	= $_[0];
		$errval	= $_[1];
	}

	if ($self->{DEBUG}) {
		print "OpenCA::OpenSSL->setError: errno:".$errno."<br>\n";
		print "OpenCA::OpenSSL->setError: errval:".$errval."<br>\n";
	}

	## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
	return undef;
}

sub genKey {

	## Generate a new key, arguments accepted are, in order
	##  ( BITS=>$bits, OUTFILE=>$outfile, ALGORITHM=>$alg, PASSWD=>$passwd )

	my $self = shift;
	my $keys = { @_ };

	my $bits    = $keys->{BITS};
	my $outfile = $keys->{OUTFILE};
	$outfile = $self->{KEY} if (not $outfile);
	my $alg     = $keys->{ALGORITHM};
	my $type    = $keys->{TYPE};
	my $passwd  = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );
	my $rand    = $keys->{RAND};

	my $command = "$self->{shell} ";

	if ($type) {
		$command .= " gen".lc $type." ";
	} else {
		$command .= " genrsa ";
	}

	if( $engine ) {
		$command .= "-engine $engine ";
	}

	if( $passwd ) {
		$command .= "-passout env:pwd ";
		$alg = "des" if ( not(defined($alg)) or $alg eq "" );
	}

	if ( defined($alg) && $alg ne "" ) {
		$command .= "-$alg ";
	}

	if ( defined($outfile) && $outfile ne "" ) {
		$command .= "-out $outfile ";
	}


	if ( defined($rand) && $rand ne "" ) {
		$command .= "-rand \Q$rand\E ";
	} else {
		$ENV{'RANDFILE'} = "/tmp/.rand_${$}";
	}

	$command .= $bits if( defined($bits) );

	## FIXME: why do we open a pipe and don't pass any data?

	$ENV{'pwd'} = "$passwd" if (defined($passwd));
	if (not open(FD, "$command|" )) {
		$self->setError (7711011, "OpenCA::OpenSSL->genKey: Cannot open pipe to OpenSSL.");
		delete ($ENV{'pwd'}) if( defined($passwd));
		return undef;
	}
	## Send Password
	## if( $passwd ) {
	## 	print FD "$passwd\n";
	## }

	## Send Confirmation Password
	## print FD "$passwd\n";
	close(FD);

	delete ($ENV{'pwd'}) if( defined($passwd));
	delete ($ENV{'RANDFILE'}) if (defined($ENV{'RANDFILE'}));

	if( not defined( $rand )) {
		unlink( "/tmp/.rand_${$}" );
	}

	if( $? != 0 ) {
		$self->setError (7711021, "OpenCA::OpenSSL->genKey: OpenSSL fails (".$?.").");
		return undef;
	}

	return 1;
}

sub genReq {

	## Generate a Request file, parameter accepted are
	## ( $outfile, $keyfile, $passwd , [email, cn, ou, o, c ] )
	## To utilize null passwd simply pass a "" reference.

	my $self = shift;
	my $keys = { @_ };

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my $outfile = $keys->{OUTFILE};
	my $outform = $keys->{OUTFORM};
	my $keyfile = $keys->{KEYFILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $subject = $keys->{SUBJECT};
	my $passwd  = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $command = "$self->{shell} req -new ";
	my $tmpfile = $self->{tmpDir} . "/${$}_req.pem";
	my ( $ret, $tmp, @DN );

	if( not $keyfile ) {
		$self->setError (7712011, "OpenCA::OpenSSL->genReq: No keyfile specified.");
		return undef;
	}

	if( defined $keys->{DN} ) {
		@DN = @{ $keys->{DN} };
	}

	## fix openssl's DN-handling
	if ($subject) {
		print "OpenCA::OpenSSL->genReq: subject_rfc2253: $subject<br>\n"
			if ($self->{DEBUG});
		my $dn_obj = X500::DN->ParseRFC2253 ($subject);
		if (not $dn_obj) {
			$self->setError (7712013,
					"OpenCA::OpenSSL->genReq: Cannot build X500::DN-object from subject $subject.");
			return undef;
		}
		$subject = $dn_obj->getOpenSSLString ();
		print "OpenCA::OpenSSL->genReq: subject_x500: $subject<br>\n"
			if ($self->{DEBUG});
	}

 	if ( defined($self->{cnf}) && $self->{cnf} ne "" ) {
		$command .= "-config " . $self->{cnf} . " ";
	}

 	$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	$command .= "-subj \Q$subject\E " if ( defined( $subject) && $subject ne "" );

	if( $engine ) {
                $command .= "-engine $engine ";
        }


	if( defined($outform) ) {
		$outform = uc( $outform );

		if ( $outform =~ /(PEM|DER)/i ) {
			$command .= "-outform $outform ";
		} elsif ( $outform =~ /(TXT)/ ) {
			$command .= "-text -noout ";
		}
  	}

	$command .= "-key $keyfile ";

	if ( $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= " >$tmpfile ";
	}
	
	$ENV{'pwd'} = "$passwd" if( defined($passwd));
	print "OpenCA::OpenSSL->genReq: command: ".$command."<br>\n"
		if ($self->{DEBUG});
	if (not open( FD, "|$command" )) {
		$self->setError (7712071, "OpenCA::OpenSSL->genReq: Cannot open pipe to OpenSSL.");
		delete( $ENV{'pwd'} ) if( defined($passwd) );
		return undef;
	}
	if( not defined ($subject) or ( $subject eq "") ) {
		foreach $tmp (@DN) {
			print FD "$tmp\n";
		}
	}
	close(FD);
	delete( $ENV{'pwd'} ) if( defined($passwd) );

	if ($? == 256) {
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->genReq: error detected<br>\n";
			print "OpenCA::OpenSSL->genReq: original errorcode: ".$?."<br>\n";
			print "OpenCA::OpenSSL->genReq: deleting error<br>\n";
		}
		$? = 0;
	}
	if( $? != 0 ) {
		$self->setError (7712073, "OpenCA::OpenSSL->genReq: OpenSSL fails (".$?.").");
		return undef;
	}

	if( not defined $outfile or $outfile eq "" ) {
		if (not open( FD, "<$tmpfile" )) {
			$self->setError (7712081, "OpenCA::OpenSSL->genReq: Cannot open tmpfile $tmpfile for reading.");
			return undef;
		}
		while( $tmp = <FD> ) {
			$ret .= $tmp;
		}
		close(FD);
		unlink( "$tmpfile" );

		return $ret;
	}

	
	return 1;
}

sub genCert {

	## Generate a new Certificate file, parameter accepted are
	## (OUTFILE=>$outfile,KEYFILE=>$keyfile,REQFILE=>$reqfile,
	## PASSWD=>$passwd, DN=>[ @list ] )

	my $self = shift;
	my $keys = { @_ };

	my $outfile = $keys->{OUTFILE};
	my $keyfile = $keys->{KEYFILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $reqfile = $keys->{REQFILE};
	my $subject = $keys->{SUBJECT};
	my $noemail = $keys->{NOEMAILDN};
	my $passwd  = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $days    = $keys->{DAYS};
	my $tmpfile = $self->{tmpDir} . "/${$}_crt.tmp";

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	## fix openssl's DN-handling
	if ($subject) {
		print "OpenCA::OpenSSL->genReq: subject_rfc2253: $subject<br>\n"
			if ($self->{DEBUG});
		my $dn_obj = X500::DN->ParseRFC2253 ($subject);
		if (not $dn_obj) {
			$self->setError (7713013,
					"OpenCA::OpenSSL->genCert: Cannot build X500::DN-object from subject $subject.");
			return undef;
		}
		$subject = $dn_obj->getOpenSSLString ();
		print "OpenCA::OpenSSL->genReq: subject_x500: $subject<br>\n"
			if ($self->{DEBUG});
	}

	my $command = "$self->{shell} req -x509 ";

	my ( $ret, $tmp );

	if (not $keyfile) {
		$self->setError (7713015, "OpenCA::OpenSSL->genCert: No keyfile specified.");
		return undef;
	}
	if (not $reqfile) {
		$self->setError (7713016, "OpenCA::OpenSSL->genCert: No requestfile specified.");
		return undef;
	}

        if( $engine ) {
                $command .= "-engine $engine ";
        }

	$command .= "-subj \Q$subject\E "
		if ( defined($subject) && ($subject ne "") );

	## $command .= "-noemailDN "
	## 	if ( defined($noemail) && ($noemail ne "") );

	$command .= "-passin env:pwd " 
		if ( defined($passwd) && $passwd ne "" );

	$command .= "-config ". $self->{cnf} . " "
		if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );

	$command .= "-days $days " 
		if ( defined($days) && $days =~ /\d+/ && $days > 0 );

	$command .= "-in \Q$reqfile\E -key \Q$keyfile\E ";


	if( defined($outfile) && $outfile ne "" ) {
		$command .= "-out \Q$outfile\E ";
	} else {
		$command .= "-out \Q$tmpfile\E ";
	}

	$ENV{'pwd'} = "$passwd" if( defined($passwd) );
	$ret = `$command`;
	delete( $ENV{'pwd'} ) if( defined($passwd) );

	if( $? != 0 ) {
		$self->setError (7713071, "OpenCA::OpenSSL->genCert: OpenSSL failed (".$?.").");
		return undef;
	}

	if( not(defined($outfile)) or $outfile eq "" ) {
		if (not open( FD, "<$tmpfile" )) {
			$self->setError (7713081, "OpenCA::OpenSSL->genCert: Cannot open tmpfile $tmpfile for reading.");
			return undef;
		}
		while( $tmp = <FD> ) {
			$ret .= $tmp;
		}
		close(FD);
		unlink( "$tmpfile" );
	}

	return "$ret";
}

sub crl2pkcs7 {
	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $crlfile = $keys->{CRLFILE};
	my $inform  = $keys->{INFORM};
	my $outfile = $keys->{OUTFILE};
	my $outform = $keys->{OUTFORM};

	my ( $ret, $tmp, $tmpfile, $command, $nocrl );
	$command = "$self->{shell} crl2pkcs7 ";

	if( (not(defined($data)) or $data eq "") and
			(not(defined($crlfile)) or $crlfile eq "" )) {
		$nocrl = 1;
		$command .= "-nocrl ";
	} else {
		$nocrl = 0;
	}

	if ( not defined $crlfile or $crlfile eq "" ){
		$tmpfile = $self->{tmpDir} . "/${$}_incrl.tmp";
		if (not open( FD, ">$tmpfile" )) {
			$self->setError (7721011, "OpenCA::OpenSSL->crl2pkcs7: Cannot open tmpfile $tmpfile for writing.");
			return undef;
		}
		print FD "$data";
		close( FD );
	} else {
		$tmpfile = $crlfile;
	}
	$command .= "-in $tmpfile " if( $nocrl == 1 );

	$command .= "-out $outfile "
		if ( defined($outfile) and $outfile ne "");
	$command .= "-inform $inform "
		if ( defined($inform) and $inform ne "");
	$command .= "-outform $outform "
		if ( defined($outform) and $outform ne "");

	if( defined $keys->{CERTSLIST} ) {
		my @certs = @{ $keys->{CERTSLIST}};

		for (@certs) {
			$command .= "-certfile \Q$_\E "
				if( ("$_" ne "") and (-f "$_") );
		}
	}

	$ret = `$command`;
	if($? != 0) {
		$self->setError (7721071, "OpenCA::OpenSSL->crl2pkcs7: OpenSSL fails (".$?.").");
		$ret = undef;
	} else {
		$ret = 1 if( $outfile ne "" );
	}
	unlink("$tmpfile") if ( $crlfile eq "" );

	return $ret;
}

sub dataConvert {

	## You can convert data structures to different formats
	## Accepted parameters are:
	##
	##    DATATYPE=> CRL|CERTIFICATE|REQUEST|KEY
	##    OUTFORM => PEM|DER|NET|TXT|PKCS12|PKCS8
	##    INFORM  => PEM|DER|NET|TXT|PKCS12|PKCS8
	##    OUTFILE => $outfile
	##    INFILE  => $infile
	##    DATA    => $data
	##    KEYFILE => $keyfile
	##    CACERT  => $cacert

	##    PKCS12 encode parameter :
	##    INFILE or DATA (must be PEM encoded)
	##    KEYFILE (might be in front of the DATA or in INFILE)
	##    P12PASSWD = password for pkcs12 file (optional)
	##    PASSWD  = password for KEYFILE (optional)
	##    INPASSWD  = password for KEYFILE (optional)
	##    OUTPASSWD  = password for KEYFILE (optional)
	##    OUTFILE = optional
	##    ALGO    = optionl, default = des3
	##    DATATYPE must be 'CERTIFICATE'
	##    CACERT	= add additional cacert to pkcs#12

	##    PKCS12 decode parameter
	##    INFILE or DATA (must be PKCS12 encoded)
	##    P12PASSWD
	##    PASSWD (PEM password optional)
	##    OUTFILE = optional
	##    DATATYPE must be 'CERTIFICATE'	

	##    KEY encode/decode parameter
	##    PUBOUT = true value - output only the public key?
	##    PUBIN  = true value - input is only the public key?

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $type    = $keys->{DATATYPE};
	my $outform = $keys->{OUTFORM};
	my $encoding= $keys->{ENCODING};
	my $inform  = $keys->{INFORM};
	my $outfile = $keys->{OUTFILE};
	my $infile  = $keys->{INFILE};
	my $keyfile = $keys->{KEYFILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $passwd  = $keys->{'PASSWD'};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $p12pass = $keys->{'P12PASSWD'};
	my $inpwd   = $keys->{'INPASSWD'};
	my $outpwd  = $keys->{'OUTPASSWD'};
	my $algo    = $keys->{'ALGO'} || 'des3';
	my $nokeys  = $keys->{'NOKEYS'};
	my $cacert  = $keys->{'CACERT'};
	$cacert = $self->{CERT} if (not $cacert);
	my $pubin   = $keys->{'PUBIN'};
	my $pubout  = $keys->{'PUBOUT'};

	my ( $command, $tmp, $ret, $tmpfile );

	## rest errordetection
	if( $? != 0 ) {
		print "OpenCA::OpenSSL->dataConvert: resetting error from ${?} to 0<br>\n"
			if ($self->{DEBUG});
		$? = 0;
	}
	if( $errno != 0 ) {
		print "OpenCA::OpenSSL->dataConvert: resetting errno from $errno to 0<br>\n"
			if ($self->{DEBUG});
		$self->setError (0, "");
	}

	if ( not $type) {
		$self->setError (7722011, "OpenCA::OpenSSL->dataConvert: No datatype specified.");
		return undef;
	}
	if ( (not $data) and (not $infile) and ($type =~ /KEY/)) {
		$infile = $self->{KEY};
	}
	if ( (not $data) and (not $infile)) {
		$self->setError (7722012, "OpenCA::OpenSSL->dataConvert: No input data specified.");
		return undef;
	}
	if ( not $algo =~ /des3|des|idea/ ) {
		$self->setError (7722013, "OpenCA::OpenSSL->dataConvert: Unsupported algorithm specified.");
		return undef;
	}
	if ( defined($nokeys) and ($outform eq 'PKCS12') ) {
		$self->setError (7722014,
				"OpenCA::OpenSSL->dataConvert: No keys available but the output format is PKCS#12.");
		return undef;
	}

	## Return if $infile does not exists
	if( $infile and ( not -e $infile )) {
		$self->setError (7722015, "OpenCA::OpenSSL->dataConvert: The specified inputfile doesn't exist.");
		return undef;
	}
	if (not $infile) {
		$infile = $self->{tmpDir} . "/${$}_data.tmp";
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->dataConvert: create temporary infile $infile<br>\n";
			print "OpenCA::OpenSSL->dataConvert: the data is like follows<br>\n";
			print "$data<br>\n";
		}
		if (not  open FD, ">".$infile) {
			print "OpenCA::OpenSSL->dataConvert: failed to open temporary infile $infile<br<\n"
				if ($self->{DEBUG});
			$self->setError (7722041,
					"OpenCA::OpenSSL->dataConvert: Cannot write inputdata to tmpfile $infile.");
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}

	$outform = "PEM" if( not $outform ); 
	$inform  = "PEM" if( not $inform ); 

	$tmpfile = "$self->{tmpDir}/${$}_cnv.tmp";
	$command = "$self->{shell} ";

	if( $type =~ /CRL/i ) {
		$command .= " crl ";
	} elsif ( $type =~ /CERTIFICATE/i ) {
		if( $outform eq 'PKCS12' or $inform eq 'PKCS12' ) {
			$command .= ' pkcs12 ';
		} else {
			$command .= " x509 -nameopt RFC2253 ";
		}
	} elsif ( $type =~ /REQ/i ) {
		$command .= " req -nameopt RFC2253 ";
 		if ( defined($self->{cnf}) && $self->{cnf} ne "" ) {
			$command .= "-config " . $self->{cnf} . " ";
		}
	} elsif ( $type =~ /KEY/i ) {
		## PKCS8 enforces PEM because the OpenSSL command req can
		## only handle PEM-encoded PKCS#8 keys
		if ( ($outform =~ /PKCS8/i) or ($inform =~ /PKCS8/i) ) {
			$command .= " pkcs8 ";
		} else {
			$command .= " rsa ";
		}
		if ( $pubout ) {
			$command .= " -pubout ";
		}
		if ( $pubin ) {
			$command .= " -pubin ";
		}
		if (not $inpwd) {
			$inpwd = $passwd;
		}
		if (not $inpwd) {
			## unlink ($infile) if ($data);
			## $self->setError (7722018,
			## 		"OpenCA::OpenSSL->dataConvert: Cannot convert key without input passphrase.");
			## return undef;
		} else {
			$command .= ' -passin env:inpwd ';
		}
		if (not $outpwd) {
			$outpwd = $passwd;
		}
		if (not $outpwd) {
			## unlink ($infile) if ($data);
			## $self->setError (7722019,
			## 		"OpenCA::OpenSSL->dataConvert: Cannot convert key without output passphrase.");
			## return undef;

			## I had to comment this one out. In my version of
			## openssl (0.9.7a-1) it is not necessary nor
			## recognized.
			#$command .= ' -nocrypt ';
		} else {
			$command .= ' -passout env:outpwd ';
		}
	} else {
		## if no known type is given...
		$self->setError (7722021,
				"OpenCA::OpenSSL->dataConvert: The datatype which should be converted is not known.");
		unlink ($infile) if ($data);
		return undef;
	}

	$outfile = $tmpfile if ( not $outfile );

	$command .= "-out $outfile ";
	$command .= "-in $infile "; 
	$command .= "-inkey $keyfile " if( defined($keyfile) and ($inform eq 'PKCS12' or $outform eq 'PKCS12')); #PKCS12 only

	# outform in PKCS12 is always PEM
	if( $outform =~ /TXT/i ) {
		$command .= "-text -noout ";
	} elsif ( $outform =~ /(PEM|DER|NET)/i ) {
		if( $inform eq 'PKCS12' ) {
			$command .= '-passout env:pempwd 'if( defined($passwd) );
			$command .= '-passin env:p12pwd ' if( defined($p12pass) );
			$command .= '-nokeys ' if( defined($nokeys) );
			if( defined($passwd) ) {
	                        $command .= "-$algo " if( $algo eq 'des' or
                                                          $algo eq 'des3' or
                                                          $algo eq 'idea' );
			} else {
				$command .= '-nodes' if( not defined($passwd) );
			}
		} else {
			$command .= "-outform " . uc($outform) . " ";
		}
	} elsif ( $outform eq 'PKCS12' ) {
		$command .= "-export ";
		$command .= '-passout env:p12pwd ';
		$command .= '-passin env:pempwd ' if( defined($passwd) );
		$command .= "-certfile $cacert " if(defined($cacert));
	} elsif ( $outform =~ /PKCS8/i ) {
		$command .= " -topk8 ";
		if ($encoding) {
			$command .= " -outform ".uc($encoding)." ";
		} else {
			$command .= " -outform PEM ";
		}
	} else {
		## no valid format received...
		print "OpenCA::OpenSSL->dataConvert: failed to determine the output format ($outform)<br>\n"
			if ($self->{DEBUG});
		unlink ($infile) if ($data);
		$self->setError (7722024,
				"OpenCA::OpenSSL->dataConvert: The output format is unknown or unsupported.");
		return undef;
	}

	if( $outform ne 'PKCS12' ) {
		if( $inform =~ /(PEM|DER|NET)/i ) {
			$command .= "-inform " . uc($inform) ." ";
		} elsif( $inform eq 'PKCS12' ) {
	 		# nothing to do here.
		} elsif( $inform eq 'PKCS8' ) {
	 		# nothing to do here.
		} else {
			## no valid format received ...
			print "OpenCA::OpenSSL->dataConvert: failed to determine the input format ($inform)<br>\n"
				if ($self->{DEBUG});
			unlink ($infile) if ($data);
			$self->setError (7722026,
					"OpenCA::OpenSSL->dataConvert: You don't try to convert to PKCS#12 but the".
					" input format is unknown or unsupported.");
			return undef;
		}
	}

	if ($self->{DEBUG}) {
		print "OpenCA::OpenSSL->dataConvert: p12pass is set<br>\n" if( defined($p12pass) );
		print "OpenCA::OpenSSL->dataConvert: passwd is set<br>\n" if( defined($passwd) );
		print "OpenCA::OpenSSL->dataConvert: inpwd is set<br>\n" if( defined($inpwd) );
		print "OpenCA::OpenSSL->dataConvert: outpwd is set<br>\n" if( defined($outpwd) );
		print "OpenCA::OpenSSL->dataConvert: command=\Q$command\E<br>\n";
	}

	if( $? != 0 ) {
		$self->setError (7722069, "OpenCA::OpenSSL->dataConvert: ".
				"Unkown Error detected before OpenSSL starts (".$?.").");
		unlink ($infile) if ($data);
		return undef;
	}

	$ENV{'p12pwd'} = "$p12pass" if( defined($p12pass) );
	$ENV{'pempwd'} = "$passwd"  if( defined($passwd) );
	$ENV{'inpwd'}  = "$inpwd"   if( defined($inpwd) );
	$ENV{'outpwd'} = "$outpwd"  if( defined($outpwd) );

	if( defined($infile) && $infile ne "" ) {
		print "OpenCA::OpenSSL->dataConvert: using infile<br>\n" if ($self->{DEBUG});
		$ret=`$command`;
	} else {
		print "OpenCA::OpenSSL->dataConvert: piping data<br>\n" if ($self->{DEBUG});
		print "OpenCA::OpenSSL->dataConvert: data<br>\n$data<br>\n" if ($self->{DEBUG});
		if (not open( FD, "|$command" )) {
			$self->setError (7722071,
					"OpenCA::OpenSSL->dataConvert: Cannot open pipe to OpenSSL.");
			unlink ($infile) if ($data);
			delete($ENV{'pwd'});
			delete($ENV{'pempwd'});
			delete($ENV{'inpwd'});
			delete($ENV{'outpwd'});
			return undef;
		}
		print FD "$data";
		close( FD );
	}
	print "OpenCA::OpenSSL->dataConvert: openssl itself successful<br>\n" if ($self->{DEBUG});

	delete($ENV{'pwd'});
	delete($ENV{'pempwd'});
	delete($ENV{'inpwd'});
	delete($ENV{'outpwd'});
	print "OpenCA::OpenSSL->dataConvert: passphrases deleted<br>\n" if ($self->{DEBUG});

	if( $? != 0 ) {
		if ( ($? == 256) and ($outform =~ /TXT/i) ) {
			$? = 0;
		} else {
			$self->setError (7722073, "OpenCA::OpenSSL->dataConvert: OpenSSL failed (".$?.").");
			unlink ($tmpfile) if (not $keys->{OUTFILE});
			unlink ($infile) if ($data);
			return undef;
		}
	}

	unlink ($infile) if ($data);

	if( $? != 0 ) {
		$self->setError (7722075, "OpenCA::OpenSSL->dataConvert: OpenSSL failed (".$?.").");
		unlink ($tmpfile) if (not $keys->{OUTFILE});
		return undef;
	}

	if( $keys->{OUTFILE} ) {
		print "OpenCA::OpenSSL->dataConvert: return 1 and infile deleted if temporary<br>\n" if ($self->{DEBUG});
		return 1;
	}

	$ret = "";
	if (not open( TMP, "<$outfile" )) {
		print "OpenCA::OpenSSL->dataConvert: cannot read outfile $outfile<br>\n" if ($self->{DEBUG});
		$self->setError (7722081, "OpenCA::OpenSSL->dataConvert: Cannot open outfile $outfile for reading.");
		return undef;
	}
	while( $tmp = <TMP> ) {
		$ret .= $tmp;
	}
	close( TMP );
	unlink ($outfile);

	print "OpenCA::OpenSSL->dataConvert: return result like follows<br>\n" if ($self->{DEBUG});
	print "$ret<br>\n" if ($self->{DEBUG});
	return $ret;
		
}

sub issueCert {

	## Use this function to issue a certificate using the
	## ca utility. Use this if you already own a valid CA
	## certificate. Accepted parameters are:

	## REQDATA     => $data
	## REQFILE     => $reqfilename
	## INFORM      => PEM|DER|NET|SPKAC   ; defaults to PEM
	## PRESERVE_DN => Y/N		  ; defaults to Y/N
	## CAKEY       => $CAkeyfile
	## CACERT      => $CAcertfile
	## DAYS        => $days
	## PASSWD      => $passwd
	## EXTS        => $extentions
	## NOEMAILDN   => -noemailDN
	## NOUNIQUEDN  => -nouniqueDN

	my $self = shift;
	my $keys = { @_ };

	my $reqdata  = $keys->{REQDATA};
	my $reqfile  = $keys->{REQFILE};
	my $inform   = $keys->{INFORM};
	my $preserve = ( $keys->{PRESERVE_DN} or "N" );
	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $days     = $keys->{DAYS};
	my $startDate= $keys->{START_DATE};
	my $endDate  = $keys->{END_DATE};
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $exts     = $keys->{EXTS};
	my $extFile  = $keys->{EXTFILE};
	my $subject  = $keys->{SUBJECT};

	my $reqfiles =$keys->{REQFILES};
	my $outdir   =$keys->{OUTDIR};
	my $caName   = $keys->{CA_NAME};
	
	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my ( $ret, $tmpfile );

	## fix openssl's DN-handling
	if ($subject) {

		## OpenSSL includes a bug in -nameopt RFC2253
		## = signs are not escaped if they are normal values
		my $i = 0;
		my $now = "name";
		while ($i < length ($subject))
		{
			if (substr ($subject, $i, 1) =~ /\\/)
			{
				$i++;
			} elsif (substr ($subject, $i, 1) =~ /=/) {
				if ($now =~ /value/)
				{
					## OpenSSL forgets to escape =
					$subject = substr ($subject, 0, $i)."\\".substr ($subject, $i);
					$i++;
				} else {
					$now = "value";
				}
			} elsif (substr ($subject, $i, 1) =~ /,/) {
				$now = "name";
			}
			$i++;
		}

		print "OpenCA::OpenSSL->issueCert: subject_rfc2253: $subject<br>\n"
			if ($self->{DEBUG});
		my $dn_obj = X500::DN->ParseRFC2253 ($subject);
		if (not $dn_obj) {
			print "OpenCA::OpenSSL->issueCert: cannot create X500::DN-object<br>\n"
				if ($self->{DEBUG});
			$self->setError (7731001, "OpenCA::OpenSSL->issueCert: Cannot create X500::DN-object.");
			return undef;
		}
		$subject = $dn_obj->getOpenSSLString ();
		print "OpenCA::OpenSSL->issueCert: subject_x500: $subject<br>\n"
			if ($self->{DEBUG});
	}

	#return if( (not $reqdata) and (not $reqfile));
	# to make multi certs you need to tell openssl 
	# what directory to put it.
	if( (not $reqdata) and (not $reqfile) and
	    ((not $reqfiles) or (not $outdir)) ) {
		$self->setError (7731011, "OpenCA::OpenSSL->issueCert: No request specified.");
		return undef;
	}
	if (not $reqfile and not $reqfiles) {
		$reqfile = $self->{tmpDir} . "/${$}_req.tmp";
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->issueCert: create temporary reqfile $reqfile<br>\n";
			print "OpenCA::OpenSSL->issueCert: the data is like follows<br>\n";
			print "$reqdata<br>\n";
		}
		if (not  open FD, ">".$reqfile) {
			print "OpenCA::OpenSSL->issueCertConvert: failed to open temporary reqfile $reqfile<br<\n"
				if ($self->{DEBUG});
			$self->setError (7731015,
					"OpenCA::OpenSSL->issueCert: Cannot write inputdata to tmpfile $reqfile.");
			return undef;
		}
		print FD $reqdata;
		close FD;
	} else {
		$reqdata = 0;
	}

	$inform   = "PEM" if( not $inform ); 

	my $command = "$self->{shell} ca -batch ";

        if( $engine ) {
                $command .= "-engine $engine ";
        }

	$command .= "-config " .$self->{cnf}." " if ( $self->{cnf} );
	$command .= "-keyfile $cakey " if( $cakey );
	$command .= "-passin env:pwd " if ( $passwd ne "" );
	$command .= "-days $days " if ( $days );
	$command .= "-extfile $extFile " if ( $extFile );
	$command .= "-extensions $exts " if ( $exts );
	$command .= "-preserveDN " if ( $preserve =~ /Y/i );
	$command .= "-startdate $startDate " if ( $startDate );
	$command .= "-enddate $endDate " if ( $endDate );
	$command .= "-name $caName " if ( $caName );
	$command .= "-subj \Q$subject\E " if ( $subject );
	$command .= "-noemailDN " if ( $keys->{NOEMAILDN} );
	$command .= "-nouniqueDN " if ( $keys->{NOUNIQUEDN} );

	if( $inform =~ /(PEM|DER|NET)/i ) {

		#this has to be the last option
		$command .= "-outdir $outdir " if ($outdir);
		$command .=  "-infiles @$reqfiles" if ($reqfiles);

		$command .= "-in $reqfile " if ( $reqfile );
	} elsif ( $inform =~ /SPKAC/ ) {
		if ( not $reqfile ) {
			$self->setError (7731012,
					"OpenCA::OpenSSL->issueCert: You must specify a requestfile if you use SPKAC.");
			return undef;
		}
		$command .= "-spkac $reqfile ";
	} else {
		## no valid format received ...
		$self->setError (7731013,
				"OpenCA::OpenSSL->issueCert: The requests format ($inform) is not supported.");
		return undef;
	}

	## running the OpenSSL command
	print "OpenCA::OpenSSL->issueCert: openssl=\Q$command\E<br>\n"
		if ($self->{DEBUG});
	$ENV{'pwd'} = "$passwd";
	if (not open( FD, "$command 2>&1|" )) {
		$self->setError (7731073, "OpenCA::OpenSSL->issueCert: Cannot open pipe to OpenSSL.");
		delete ($ENV{'pwd'});
		return undef;
	}
	$ret = join ('', <FD>);
	close(FD);
	delete ($ENV{'pwd'});
	unlink ($reqfile) if ($reqdata);
	if( $? != 0) {
		$self->setError (7731075, "OpenCA::OpenSSL->issueCert: OpenSSL fails (".$?.": ".$ret.").");
		return undef;
	}

	print "OpenCA::OpenSSL->issueCert: certificate issued successfully<br>\n"
		if ($self->{DEBUG});
	return 1;
}

sub revoke {

	## CAKEY  => $CAkeyfile (Optional)
	## CACERT => $CAcertfile (Optional)
	## PASSWD => $passwd (Optional - if not needed)
	## INFILE => $certFile (PEM Formatted certificate file);
	## CRL_REASON => Reason for revocation
	## 	unspecified
	##	keyCompromise
	##	CACompromise
	##	affiliationChanged
	## 	superseded
	##	cessationOfOperation
	##	certificateHold
	##	removeFromCRL
	##	holdInstruction
	##	keyTime
	##	CAkeyTime

	my $self = shift;
	my $keys = { @_ };

	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $cacert   = $keys->{CACERT};
	$cacert = $self->{CERT} if (not $cacert);
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $certFile = $keys->{INFILE};
	my $crlReason= $keys->{CRL_REASON};

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my ( $tmp, $ret );
	my $command = "$self->{shell} ca -revoke \Q$certFile\E ";

	if (not $certFile) {
		$self->setError (7732011, "OpenCA::OpenSSL->revoke: No inputfile specified.");
		return undef;
	}

        if( $engine ) {
                $command .= "-engine $engine ";
        }

	$command .= "-config " . $self->{cnf}. " " if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( defined($cakey) && $cakey ne "" );
	$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	$command .= "-cert $cacert " if ( defined($cacert) && $cacert ne "" );
	$command .= "-nouniqueDN " if ( $keys->{NOUNIQUEDN} );
	$command .= "-crl_reason $crlReason " if ( $keys->{CRL_REASON} );

	$ENV{'pwd'} = "$passwd";
	if (not open( FD, "$command 2>&1|" )) {
		$self->setError (7732071, "OpenCA::OpenSSL->revoke: Cannot open pipe to OpenSSL.");
		delete ($ENV{'pwd'});
		return undef;
	}
	while( $tmp = <FD> ) {
		$ret .= $tmp;
	}
	close(FD);
	delete ($ENV{'pwd'});
	if( $? != 0) {
		$self->setError (7732073, "OpenCA::OpenSSL->revoke: OpenSSL failed (".$?.": ".$ret.").");
		return undef;
	} else {
		return 1;
	}
}


sub issueCrl {

	## CAKEY   => $CAkeyfile
	## CACERT  => $CAcertfile
	## PASSWD  => $passwd
	## DAYS    => $days
	## EXTS    => $extentions
	## OUTFILE => $outfile
	## OUTFORM => PEM|DER|NET|TXT

	my $self = shift;
	my $keys = { @_ };

	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $cacert   = $keys->{CACERT};
	$cacert = $self->{CERT} if (not $cacert);
	my $days     = $keys->{DAYS};
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $outfile  = $keys->{OUTFILE};
	my $outform  = $keys->{OUTFORM};
	my $exts     = $keys->{EXTS};
	my $extfile  = $keys->{EXTFILE};

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );
	
	my ( $ret, $tmp, $tmpfile );
	my $command = "$self->{shell} ca -gencrl ";

        if( $engine ) {
                $command .= "-engine $engine ";
        }

	if ( not defined $outfile or $outfile eq "" ){
		$tmpfile = $self->{tmpDir} . "/${$}_crl.tmp";
	} else {
		$tmpfile = $outfile;
	}
	$command .= "-out $tmpfile ";

	$command .= "-config " . $self->{cnf}. " " if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( defined($cakey) && $cakey ne "" );
	$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	$command .= "-cert $cacert " if ( defined($cacert) && $cacert ne "" );
	$command .= "-crldays $days " if ( defined($days) && $days ne "" );
	$command .= "-crlexts $exts " if ( defined($exts) && $exts ne "" );
	$command .= "-extfile $extfile " if ( defined($extfile) && $extfile ne "" );
	$command .= "-nouniqueDN " if ( $keys->{NOUNIQUEDN} );

	$ENV{'pwd'} = "$passwd";
	$ret = `$command`;
	delete( $ENV{'pwd'} );

	if( $? != 0) {
		$self->setError (7733071, "OpenCA::OpenSSL->issueCrl: OpenSSL failed (".$?.").");
		return undef;
	}

	$ret = $self->dataConvert( INFILE  =>$tmpfile,
				   OUTFORM =>$outform,
				   DATATYPE=>"CRL" );

	if( not $ret ) {
		## the error occurs in dataConvert so we don't change the errorcode itself
		$self->{errval} = "OpenCA::OpenSSL->issueCrl: Errorcode 7733082:\n".$self->{errval};
		return undef;
	}

	if( defined($outfile) && $outfile ne "" ) {
		if (not open( FD, ">$outfile" )) {
			$self->setError (7733084, "OpenCA::OpenSSL->issueCrl: Cannot open outfile $outfile for writing.");
			return undef;
		}
		print FD "$ret";
		close( FD );
		return 1;
	}

	unlink( $tmpfile );
	return "$ret";
}

sub SPKAC {

	my $self = shift;
	my $keys = { @_ };

	my $infile  = $keys->{INFILE};
	my $outfile = $keys->{OUTFILE};
	my $spkac   = $keys->{SPKAC};

	my $command = $self->{shell} . " spkac -verify ";
	my $tmpfile = $self->{tmpDir} . "/${$}_SPKAC.tmp";

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my $ret = "";
	my $retVal = 0;
	my $tmp;

	if( defined($spkac) && $spkac ne "" ) {
		$infile = $self->{tmpDir} . "/${$}_in_SPKAC.tmp";
		if (not open( FD, ">$infile" )) {;
			$self->setError (7741011, "OpenCA::OpenSSL->SPKAC: Cannot open infile $infile for writing.");
			return undef;
		}
		print FD "$spkac\n";
		close ( FD );
	}

        if( $engine ) {
                $command .= "-engine $engine ";
        }

	$command .= "-in $infile " if( defined($infile) && $infile ne "" );
	if( defined($outfile) && $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= "-out $tmpfile ";
	}

	if (not open( FD, "|$command" )) {
		$self->setError (7741071, "OpenCA::OpenSSL->SPKAC: Cannot open pipe to OpenSSL.");
		return undef;
	}
	close( FD );

	## Store the ret value
	$retVal = $?;

	## Unlink the infile if it was temporary
	unlink $infile if( defined($spkac) && $spkac ne "");

	if ($retVal != 0) {
		$self->setError (7741073, "OpenCA::OpenSSL->SPKAC: OpenSSL failed (".$retVal.").");
		return undef;
	}

	if( defined($outfile) && $outfile ne "" ) {
		return 1;
	}

	## Get the output
	if (not open( TMP, "$tmpfile" )) {
		$self->setError (7741081, "OpenCA::OpenSSL->SPKAC: Cannot open tmpfile $tmpfile.");
		return undef;
	}
	while ( $tmp = <TMP> ) {
		$ret .= $tmp;
	}
	close( TMP );
	unlink $tmpfile if (not defined $outfile or $outfile eq "");

	if ( $? != 0 ) {
		$self->setError (7741083, "OpenCA::OpenSSL->SPKAC: Cannot read tmpfile $tmpfile successfully (".$?.").");
		return undef;
	}

	return $ret;
}

sub getDigest {

	## Returns Digest of the provided message
	## DATA=>$data, ALGORITHM=>$alg

	my $self = shift;
	my $keys = { @_ };
	
	my $data    = $keys->{DATA};
	my $alg     = lc( $keys->{ALGORITHM} );
	my $tmpfile = $self->{tmpDir} . "/${$}_dgst.tmp";

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my ( $command, $ret );

	$alg = "md5" if( not $alg );

	if (not $data) {
		$self->setError (7751011, "OpenCA::OpenSSL->getDigest: No data specified.");
		return undef;
	}
	if (not open( FD, ">$tmpfile" )) {
		$self->setError (7751031, "OpenCA::OpenSSL->getDigest: Cannot open tmpfile $tmpfile for writing.");
		return undef;
	}
	print FD $data;
	close( FD );

	$command = "$self->{shell} dgst -$alg ";

        if( defined($engine) and ($engine ne "")) {
                $command .= "-engine $engine ";
        }

	$command .= "<\Q$tmpfile\E";

	$ret = `$command`;
	$ret =~ s/\n//g;

	unlink( $tmpfile );

	if( $? != 0 ) {
		$self->setError (7751071, "OpenCA::OpenSSL->getDigest: OpenSSL failed (".$?.").");
		return undef;
	} else {
		return $ret;
	}
}

sub verify {

	## Verify PKCS7 signatures (new OpenCA::verify command
	## should be used )

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	my $sig     = $keys->{SIGNATURE};
	my $sigfile = $keys->{SIGNATURE_FILE};
	my $cacert  = $keys->{CA_CERT};
	$cacert = $self->{CERT} if (not $cacert);
	my $cadir   = $keys->{CA_DIR};
	my $verbose = $keys->{VERBOSE};
	my $out	    = $keys->{OUTFILE};
	my $noChain = $keys->{NOCHAIN};
	my $tmpfile = $self->{tmpDir} . "/${$}_vrfy.tmp";
	my $command = $self->{verify} . " ";

	my ( $ret, $tmp );

	if( (not $data) and (not $datafile) ) {
		print "OpenCA::OpenSSL->verify: cannot open command<br>\n"
			if ($self->{DEBUG});
		$self->setError (7742011, "OpenCA::OpenSSL->verify: No input source specified.");
		return undef;
	}

## IE's signatures are not a problem for openca-verify
##	## load datafile to fix signature
##	if ($datafile) {
##		if (not open( TMP, "<$datafile" )) {
##			print "OpenCA::OpenSSL->verify: cannot open datafile to fix crlf<br>\n"
##				if ($self->{DEBUG});
##			$self->setError (7742021, "OpenCA::OpenSSL->verify: Cannot open datafile $datafile for reading.");
##			return undef;
##		}
##		$data = "";
##		while( not eof ( TMP ) ) {
##			$data .= <TMP>;
##		}
##		close( TMP );
##	}
##
##	## fix signatures of IE
##	## $data =~ s/\r//g;

	if (not $datafile) {
		$datafile = $self->{tmpDir} . "/${$}_data.tmp";
		if (not open (FD, ">".$datafile)) {
			$self->setError (7742023, "OpenCA::OpenSSL->verify: Cannot open datafile $datafile for writing.");
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}

	if (not $sigfile) {
		$sigfile = $self->{tmpDir} . "/${$}_sig.tmp";
		if (not open (FD, ">".$sigfile)) {
			$self->setError (7742025, "OpenCA::OpenSSL->verify: Cannot open sigfile $sigfile for writing.");
			unlink $datafile if ($data);
			return undef;
		}
		print FD $sig;
		close FD;
		$sig = 1;
	} else {
		$sig = 0;
	}

	$command   .= "-verbose " if ( $verbose );
	$command   .= "-cf $cacert " if ( $cacert );
	$command   .= "-cd $cadir " if ($cadir);
	$command   .= "-data $datafile " if ($datafile);
	## the user should know what he's doing
	## $command   .= "-no_chain " if ( $noChain and not($cacert or $cadir));
	$command   .= "-no_chain " if ( $noChain );
	$command   .= "-in $sigfile" if ( $sigfile );
	$command   .= ">\Q$out\E " if ( $out );

	if( not $out ) {
		$command .= " >\Q$tmpfile\E";
	}

	$command .= " 2>\&1";

	print "OpenCA::OpenSSL->verify: command=\Q$command\E<br>\n"
		if ($self->{DEBUG});

	$ret =`$command`;
	my $org_err = $?;

	unlink ($datafile ) if ($data);
	unlink ($sigfile)   if ($sig);

	$ret = "";
	if (not open( TMP, "<$tmpfile" )) {
		print "OpenCA::OpenSSL->verify: Cannot open tmpfile<br>\n"
			if ($self->{DEBUG});
		$self->setError (7742082, "OpenCA::OpenSSL->verify: Cannot open tmpfile $tmpfile for reading.");
		return undef;
	}
	while( not eof ( TMP ) ) {
		$ret .= <TMP>;
	}
	close( TMP );

	if ( $? == 256 ) {
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->verify: error detected<br>\n";
			print "OpenCA::OpenSSL->verify: original errorcode: ".$?."<br>\n";
			print "OpenCA::OpenSSL->verify: deleting error<br>\n";
		}
		$? = 0;
	} elsif ( $? != 0 ) {
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->verify: error detected<br>\n";
			print "OpenCA::OpenSSL->verify: original errorcode: ".$?."<br>\n";
		}
		(my $h) = 
			( $ret =~ /(Verify Error\s*.*?\s*:\s*.*?)\n/ );
		$self->setError (7742073, "OpenCA::OpenSSL->verify: openca-verify failed (".$org_err."):\n".$h);
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->verify: errorcode: ".$self->errno()."<br>\n";
			print "OpenCA::OpenSSL->verify: errormsg: ".$self->errval()."<br>\n";
		}
		unlink( $tmpfile ) if (not $out);
		return undef;
	}

	print "OpenCA::OpenSSL->verify: returned data:\n<br>".$ret."<br>\n"
		if ($self->{DEBUG});
	if( not $out) {
		unlink( $tmpfile );
		print "OpenCA::OpenSSL->verify: finished successfully (return output)<br>\n"
			if ($self->{DEBUG});
		return $ret;
	} else {
		print "OpenCA::OpenSSL->verify: finished successfully (return 1)<br>\n"
			if ($self->{DEBUG});
		return 1;
	}
}

sub sign {

	## Generate a PKCS7 signature.

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	my $out     = $keys->{OUT_FILE};
	my $certfile= $keys->{CERT_FILE};
	$certfile = $self->{CERT} if (not $certfile);
	my $cert    = $keys->{CERT};
	my $keyfile = $keys->{KEY_FILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $key     = $keys->{KEY};
	my $nonDetach = $keys->{INCLUDE_DATA};
	my $pwd     = ( $keys->{PWD} or $keys->{PASSWD} );
	$pwd = $self->{PASSWD} if (not $pwd);
	my $tmpfile = $self->{tmpDir} . "/${$}_sign.tmp";
	my $command = $self->{sign} . " ";

	my ( $ret );

	if( (not $data) and (not $datafile) ) {
		$self->setError (7743011, "OpenCA::OpenSSL->sign: No input source.");
		return undef;
	}
	if( (not $cert) and (not $certfile) ) {
		$self->setError (7743012, "OpenCA::OpenSSL->sign: No certificate specified.");
		return undef;
	}
	if( (not $key)  and (not $keyfile) ) {
		$self->setError (7743012, "OpenCA::OpenSSL->sign: No private key specified.");
		return undef;
	}

	if ( not $datafile ) {
		$datafile = $self->{tmpDir} . "/${$}_data.tmp";
		if (not open FD, ">".$datafile) {
			$self->setError (7743031, "OpenCA::OpenSSL->sign: Cannot open datafile $datafile for writing.");
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}
	if ( not $keyfile ) {
		$keyfile = $self->{tmpDir} . "/${$}_key.tmp";
		if (not open FD, ">".$keyfile) {
			$self->setError (7743033, "OpenCA::OpenSSL->sign: Cannot open keyfile $keyfile for writing.");
			unlink ($datafile) if ($data);
			return undef;
		}
		print FD $key;
		close FD;
	} else {
		$key = 0;
	}
	if ( not $certfile ) {
		$certfile = $self->{tmpDir} . "/${$}_cert.tmp";
		if (not open FD, ">".$certfile) {
			$self->setError (7743035, "OpenCA::OpenSSL->sign: Cannot open certfile $certfile for writing.");
			unlink ($datafile) if ($data);
			unlink ($keyfile) if ($key);
			return undef;
		}
		print FD $cert;
		close FD;
	} else {
		$cert = 0;
	}

	$command   .= "-in $datafile ";
	$command   .= "-out $out "            if ( $out );
	$command   .= "-passin env:pwd " if ( $pwd );
	$command   .= "-nd "                  if ( $nonDetach );

	$command   .= "-cert $certfile ";
	$command   .= " -keyfile $keyfile ";

	if( not $out) {
		$command .= " >$tmpfile";
	};

        print "OpenCA::OpenSSL: the command is as follows<br>\n".
	      "$command<br>\n"
		if ($self->{DEBUG});

	$ENV{pwd} = "$pwd" if ( $pwd );
	$ret =`$command`;
	delete ($ENV{pwd});

	if ( $? == 256 ) {
		print "OpenCA::OpenSSL: Error 256 detected<br>\n".
			"OpenCA::OpenSSL: resetting error<br>\n"
			if ($self->{DEBUG});
	} elsif ( $? ) {
		unlink( $tmpfile )  if (not $out);
		unlink( $datafile ) if ($data);
		unlink( $keyfile )  if ($key);
		unlink( $certfile ) if ($cert);
		$self->setError (7743071, "OpenCA::OpenSSL->sign: openca-sign failed (".$?.").");
		return undef;
	}
	unlink( $datafile ) if ($data);
	unlink( $keyfile )  if ($key);
	unlink( $certfile ) if ($cert);

	if( not $out ) {
		if (not open( TMP, "<$tmpfile" )) {
			$self->setError (7743081, "OpenCA::OpenSSL->sign: Cannot open tmpfile $tmpfile for reading.");
			return undef;
		}
		do {
			$ret .= <TMP>;
		} while (not eof(TMP));
		close(TMP);

		unlink( $tmpfile );
	}

	## If we are here there have been no errors, so
	## if $ret is empty, let's return a true value...
	$ret = 1 if ( not $ret );

	return $ret;
}

sub getCertAttribute {
	my $self = shift;
	my $keys = { @_ };

	my $cert;
	if ($keys->{INFORM} and $keys->{INFORM} =~ /DER/)
	{
		$cert = OpenCA::OpenSSL::X509::_new_from_der ($keys->{DATA});
	} else {
		$cert = OpenCA::OpenSSL::X509::_new_from_pem ($keys->{DATA});
	}

	my @attribute = ();
	if( $keys->{ATTRIBUTE_LIST} && ref($keys->{ATTRIBUTE_LIST}) ) {
		@attribute = @{$keys->{ATTRIBUTE_LIST}};
	} else {
		@attribute = ( $keys->{ATTRIBUTE} );
	}

	return undef if (not $cert);

	my ( $ret );

	foreach my $attribute ( @attribute ) {
		$_ = uc $attribute;
		my $func;
		SWITCH: {
			$func = lc $attribute;
			if (/^NOTBEFORE$/) {$func = "notBefore"};
			if (/^NOTAFTER$/)  {$func = "notAfter"};
			if (/^DN$/)        {$func = "subject"};
			if (/^HASH$/)      {$func = "subject_hash"};
		}
		$ret->{$attribute} = $cert->$func;
	}
	return $ret;
}

sub getReqAttribute {
	my $self = shift;
	my $keys = { @_ };

	## timing test
	##
	## my $start;
	## use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
	## $start = [gettimeofday];

	my $csr;
	if ($keys->{INFORM} and $keys->{INFORM} =~ /DER/)
	{
		$csr = OpenCA::OpenSSL::PKCS10::_new_from_der ($keys->{DATA});
	} elsif ($keys->{INFORM} and $keys->{INFORM} =~ /SPKAC/) {
		$csr = OpenCA::OpenSSL::SPKAC::_new ($keys->{DATA});
	} else {
		$csr = OpenCA::OpenSSL::PKCS10::_new_from_pem ($keys->{DATA});
	}

	my @attribute = ();
	if( $keys->{ATTRIBUTE_LIST} && ref($keys->{ATTRIBUTE_LIST}) ) {
		@attribute = @{$keys->{ATTRIBUTE_LIST}};
	} else {
		@attribute = ( $keys->{ATTRIBUTE} );
	}

	return undef if (not $csr);

	my ( $ret );

	foreach my $attribute ( @attribute ) {
		$_ = uc $attribute;
		my $func;
		SWITCH: {
			$func = lc $attribute;
			if (/^DN$/)        {$func = "subject"};
		}
		$ret->{$attribute} = $csr->$func;
	}

	## timing test
	##
	## if ($self->{DEBUG}) {
	## 	$errno += tv_interval ( $start ) if ($self->{DEBUG});
	## 	print "OpenCA::OpenSSL::getReqAttribute: total_time=".$errno."<br>\n";
	## }

	return $ret;
}

sub getCRLAttribute {
	my $self = shift;
	my $keys = { @_ };

	my $crl;
	if ($keys->{INFORM} and $keys->{INFORM} =~ /DER/)
	{
		$crl = OpenCA::OpenSSL::CRL::_new_from_der ($keys->{DATA});
	} else {
		$crl = OpenCA::OpenSSL::CRL::_new_from_pem ($keys->{DATA});
	}

	my @attribute = ();
	if( $keys->{ATTRIBUTE_LIST} && ref($keys->{ATTRIBUTE_LIST}) ) {
		@attribute = @{$keys->{ATTRIBUTE_LIST}};
	} else {
		@attribute = ( $keys->{ATTRIBUTE} );
	}

	return undef if (not $crl);

	my ( $ret );

	foreach my $attribute ( @attribute ) {
		$_ = uc $attribute;
		my $func;
		SWITCH: {
			$func = lc $attribute;
			if (/^LASTUPDATE$/) {$func = "lastUpdate"};
			if (/^NEXTUPDATE$/) {$func = "nextUpdate"};
			if (/^DN$/)         {$func = "issuer"};
		}
		$ret->{$attribute} = $crl->$func;
	}
	return $ret;
}

sub pkcs7Certs {

	my $self = shift;
	my $keys = { @_ };

	my $infile  = $keys->{INFILE};
	my $outfile = $keys->{OUTFILE};
	my $pkcs7   = $keys->{PKCS7};

	my $command = $self->{shell} . " pkcs7 -print_certs ";
	my $tmpfile = $self->{tmpDir} . "/${$}_SPKAC.tmp";

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my $ret = "";
	my $retVal = 0;
	my $tmp;

	if( defined($pkcs7) && $pkcs7 ne "" ) {
		$infile = $self->{tmpDir} . "/${$}_in_SPKAC.tmp";
		if (not open( FD, ">$infile" )) {
			print "OpenCA::OpenSSL->pkcs7Certs: cannot open infile $infile<br>\n"
				if ($self->{DEBUG});
			$self->setError (7744021, "OpenCA::OpenSSL->pkcs7Certs: Cannot open infile $infile for writing.");
			return undef;
		}
		print FD "$pkcs7\n";
		close ( FD );
	}

        if( defined($engine) and ($engine ne "")) {
                $command .= "-engine $engine ";
        }

	$command .= "-in $infile " if( defined($infile) && $infile ne "" );
	if( defined($outfile) && $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= "-out $tmpfile ";
	}

	print "OpenCA::OpenSSL->pkcs7Certs: command=\Q$command\E<br>\n"
		if ($self->{DEBUG});
	$ret = `$command 2>&1`;
	if( $? > 0 ) {
		$self->setError (7744071, "OpenCA::OpenSSL->pkcs7Certs: OpenSSL failed (".$?.": ".$ret.").");
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->pkcs7Certs: error detected<br>\n";
			print "OpenCA::OpenSSL->pkcs7Certs: errno=".$self->errno()."<br>\n";
			print "OpenCA::OpenSSL->pkcs7Certs: errmsg=".$self->errval()."<br>\n";
		}
	}

	## Unlink the infile if it was temporary
	unlink $infile if( defined($pkcs7) && $pkcs7 ne "");

	## Get the output
	if (not open( TMP, "$tmpfile" )) {
		print "OpenCA::OpenSSL->pkcs7Certs: cannot open tmpfile $tmpfile<br>\n"
			if ($self->{DEBUG});
		$self->setError (7744081, "OpenCA::OpenSSL->pkcs7Certs: Cannot open tmpfile $tmpfile for reading.");
		return undef;
	}
	while ( $tmp = <TMP> ) {
		$ret .= $tmp;
	}
	close( TMP );
	unlink $tmpfile if (not (defined($outfile)) or $outfile eq "");

	if ( $self->errno() != 0 ) {
		print "OpenCA::OpenSSL->pkcs7Certs: return undef because of an error<br>\n"
			if ($self->{DEBUG});
		return undef;
	} else {
		print "OpenCA::OpenSSL->pkcs7Certs: finished successfully<br>\n"
			if ($self->{DEBUG});
		return $ret;
	}
}

sub updateDB {

	my $self = shift;
	my $keys = { @_ };

	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $cacert   = $keys->{CACERT};
	$cacert = $self->{CERT} if (not $cacert);
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $outfile  = $keys->{OUTFILE};

	my ( $ret, $tmp );
	my $command = "$self->{shell} ca -updatedb ";

	$command .= "-config " . $self->{cnf}. " " if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( defined($cakey) && $cakey ne "" );
	$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	$command .= "-cert $cacert " if ( defined($cacert) && $cacert ne "" );

	$ENV{'pwd'} = "$passwd";
	$ret = `$command`;
	delete( $ENV{'pwd'} );

	if( $? != 0) {
		$self->setError (7771071, "OpenCA::OpenSSL->updateDB: OpenSSL failed (".$?.").");
		return undef;
	}

	if( defined($outfile) && $outfile ne "" ) {
		if (not open( FD, ">$outfile" )) {
			$self->setError (7771081, "OpenCA::OpenSSL->updateDB: Cannot open outfile $outfile for writing.");
			return undef;
		}
		print FD "$ret";
		close( FD );
		return 1;
	}
	return "$ret";
}

sub getSMIME {

	## DECRYPT      => a true value
	## ENCRYPT      => a true value
	## SIGN         => a true value
	## CERT         => $cert
	## KEY          => $key
	## PASSWD       => $passwd
	## ENCRYPT_CERT => $enc_cert
	## SIGN_CERT    => $sign_cert
	## INFILE       => $infile
	## OUTFILE      => $outfile
	## DATA         => $message
	## MESSAGE      => $message (higher priority)
	## ENGINE       => openssl engine
	## TO           => $to
	## FROM         => $from
	## SUBJECT      => $subject

	my $self = shift;
	my $keys = { @_ };

	my $decrypt     = $keys->{DECRYPT};
	my $encrypt     = $keys->{ENCRYPT};
	my $sign        = $keys->{SIGN};
	my $cert        = $keys->{CERT};
	$cert = $self->{CERT} if (not $cert);
	my $key         = $keys->{KEY};
	$key = $self->{KEY} if (not $key);
	my $enc_cert    = $keys->{ENCRYPT_CERT};
	my $sign_cert   = $keys->{SIGN_CERT};
	my $passwd      = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $infile      = $keys->{INFILE};
	my $outfile     = $keys->{OUTFILE};
	my $message     = $keys->{DATA};
	$message        = $keys->{MESSAGE} if ($keys->{MESSAGE});
	my $to          = $keys->{TO};
	my $from        = $keys->{FROM};
	my $subject     = $keys->{SUBJECT};

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my ( $ret, $tmp, $tmpfile );

	## smime can only handle file and not stdin
	if ($message) {
		$infile = $self->{tmpDir} . "/${$}_data.msg";
		if ($self->{DEBUG}) {
			print "OpenCA::OpenSSL->dataConvert: create temporary infile $infile<br>\n";
			print "OpenCA::OpenSSL->dataConvert: the data is like follows<br>\n";
			print "$message<br>\n";
		}
		if (not  open FD, ">".$infile) {
			print "OpenCA::OpenSSL->getSMIME: failed to open temporary infile $infile<br<\n"
				if ($self->{DEBUG});
			$self->setError (7752021,
					"OpenCA::OpenSSL->getSMIME: Cannot write message to tmpfile $infile.");
			return undef;
		}
		print FD $message;
		close FD;
	} else {
		$message = 0;
	}

	## setup file with smime-message
	if ($outfile) {
	  $tmpfile = $outfile;
	} else {
	  $tmpfile = $self->{tmpDir}."/".$$."_SMIME.msg";
	}

	$enc_cert  = $cert if (not $enc_cert);
	$sign_cert = $cert if (not $sign_cert);

	my ($enc_x509, $sign_x509);
	if ($enc_cert)
	{
		$enc_x509 = OpenCA::X509->new (
		                SHELL  => $self,
		                INFILE => $enc_cert);
		if (not $enc_x509)
		{
			unlink $infile if ($message);
			return $self->setError ($OpenCA::X509::errno, $OpenCA::X509::errval);
		}
	}
	if ($sign_cert)
	{
		$sign_x509 = OpenCA::X509->new (
		                SHELL  => $self,
		                INFILE => $sign_cert);
		if (not $sign_x509)
		{
			unlink $infile if ($message);
			return $self->setError ($OpenCA::X509::errno, $OpenCA::X509::errval);
		}
	}
	

	## use OpenCA::OpenSSL::SMIME
	## this is only a wrapper for old code !!!

	## decryption
	my $smime = OpenCA::OpenSSL::SMIME->new(
	                         INFILE => $infile,
	                         SHELL => $self,
	                         ENGINE => $engine
	                         );
	if (not $smime)
	{
		unlink $infile if ($message);
		return $self->setError ($OpenCA::OpenSSL::SMIME->errno, $OpenCA::OpenSSL::SMIME->err);
	}
	if ($decrypt) {
		open(KEYF, '<', $key) or return;
		if (not $smime->decrypt(
		            CERTIFICATE  => $enc_x509,
		            KEY_PASSWORD => $passwd,
		            PRIVATE_KEY  => \*KEYF))
		{
			close (KEYF);
			unlink $infile if ($message);
			return $self->setError ($smime->errno, $smime->err);
		}
		close (KEYF);
	} else {
		## 1. signing
		if ($sign) {
			open(KEYF, '<', $key) or return;
			if (not $smime->sign(
			            CERTIFICATE  => $sign_x509,
			            KEY_PASSWORD => $passwd,
			            PRIVATE_KEY  => \*KEYF))
			{
				close (KEYF);
				unlink $infile if ($message);
				return $self->setError ($smime->errno, $smime->err);
			}
			close (KEYF);
		}
		if ($encrypt) {
			if (not $smime->encrypt(CERTIFICATE  => $sign_x509))
			{
				unlink $infile if ($message);
				return $self->setError ($smime->errno, $smime->err);
			}
		}
	}

	unlink $infile if ($message);

	## if the caller want a file then we can finish
	if( defined($outfile) && $outfile ne "" ) {
		open (OUT, ">", $outfile);
		$smime->get_mime->print(\*OUT);
		close (OUT);
		return 1;
	}

	print "OpenCA::OpenSSL: getSMIME: return data<br>\n"
		if ($self->{DEBUG});

	return $smime->get_mime->stringify;
}

sub getPIN {

	## PIN_LENGTH    => $pin_length
	## RANDOM_LENGTH => $random_length
	## LENGTH	 => $pin_length
	## ENGINE        => openssl engine

	my $self = shift;
	my $keys = { @_ };

	my $pin_length = $keys->{LENGTH};
	$pin_length    = $keys->{PIN_LENGTH} if (defined $keys->{PIN_LENGTH});
	my $length     = $keys->{RANDOM_LENGTH};

	## my $engine;
	## $engine     = ( $ENV{'engine'} or $keys->{ENGINE} ) if ($keys->{USE_ENGINE});
	my $engine     = ( $ENV{'engine'} or $keys->{ENGINE} );

	my ( $ret, $tmp, $tmpfile );

	my $command = "$self->{shell} rand -base64 ";
        if( $engine ) {
          $command .= " -engine $engine ";
        }
	if ($length) {
	  $command .= $length;
	} elsif ($pin_length) {
	  $command .= $pin_length;
	} else {
	  return undef;
	}

	## create the PIN
	my $pin;
	if (not open (FD, "$command|")) {
		$self->setError (7753071, "OpenCA::OpenSSL->getPIN: Cannot open pipe from OpenSSL.");
		return undef;
	}
	if ($pin_length) {
	  ## enforce the PIN-length
	  ## SECURITY ADVICE: it is more secure to only set the
	  ##                  number of randombytes
	  read FD, $pin, $pin_length;
	} else {
	  ## 2*$length is enough to encode $length randombytes in base64
	  read FD, $pin, 2*$length;
	}
	close FD;

	if ($? != 0) {
		$self->setError (7753073, "OpenCA::OpenSSL->getPIN: OpenSSL failed (".$?.").");
		return undef;
	}

	## remove trailing newline
	$pin =~ s/\n//g;

	if ($pin) {
		return $pin;
	} else {
		$self->setError (7753075, "OpenCA::OpenSSL->getPIN: PIN is empty.");
		return undef;
	}

}

sub getOpenSSLDate {
	my $self = shift;

	if (not defined $_[0]) {
		$self->setError (7754011, "OpenCA::OpenSSL->getOpenSSLDate: No date specified.");
		return undef;
	}
	my $date = $self->getNumericDate ( $_[0] );
	if (not defined $date) {
		$self->{errval} = "OpenCA::OpenSSL->getOpenSSLDate: Errorcode 7754021:\n".$self->{errval};
		return undef;
	}

	## remove century
	$date =~ s/^..//;

	## add trailing Z
	$date .= "Z";

	return $date; 
}

sub getNumericDate {
	my $self = shift;

	if (not defined $_[0]) {
		$self->setError (7755011, "OpenCA::OpenSSL->getNumericDate: No argument specified.");
		return undef;
	}
	my $date = $_[0];
	if (not $date) {
		$self->setError (7755012, "OpenCA::OpenSSL->getNumericDate: No date specified.");
		return undef;
	}
	my %help;
	my $new_date;

	## remove leading days like SUN or MON
	if ( $date =~ /^\s*[^\s]+\s+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)/i ) {
		$date =~ s/^\s*[^\s]+//;
	}

	##  Mar 10 19:36:45 2001 GMT

	## Month
	if ( $date =~ /^\s*JAN/i ) {
		##  january
		$help {MONTH} = "01";
	} elsif ( $date =~ /^\s*FEB/i ) {
		## february
		$help {MONTH} = "02";
	} elsif ( $date =~ /^\s*MAR/i ) {
		## march
		$help {MONTH} = "03";
	} elsif ( $date =~ /^\s*APR/i ) {
		## april
		$help {MONTH} = "04";
	} elsif ( $date =~ /^\s*MAY/i ) {
		## may
		$help {MONTH} = "05";
	} elsif ( $date =~ /^\s*JUN/i ) {
		## june
		$help {MONTH} = "06";
	} elsif ( $date =~ /^\s*JUL/i ) {
		## july
		$help {MONTH} = "07";
	} elsif ( $date =~ /^\s*AUG/i ) {
		## august
		$help {MONTH} = "08";
	} elsif ( $date =~ /^\s*SEP/i ) {
		## september
		$help {MONTH} = "09";
	} elsif ( $date =~ /^\s*OCT/i ) {
		## october
		$help {MONTH} = "10";
	} elsif ( $date =~ /^\s*NOV/i ) {
		## november
		$help {MONTH} = "11";
	} elsif ( $date =~ /^\s*DEC/i ) {
		## december
		$help {MONTH} = "12";
	} else {
		## return illegal
		$self->setError (7755022, "OpenCA::OpenSSL->getNumericDate: Illelgal month.");
		return undef;
	}

	## day
	$date =~ s/^ *//;
	$date = substr ($date, 4, length ($date)-4);
	$help {DAY} = substr ($date, 0, 2);
	$help {DAY} =~ s/ /0/;

	## hour
	$help {HOUR} = substr ($date, 3, 2);

	## minute
	$help {MINUTE} = substr ($date, 6, 2);

	## second
	$help {SECOND} = substr ($date, 9, 2);

	## year
	$help {YEAR} = substr ($date, 12, 4);

	## build date
	$new_date =	$help {YEAR}.
			$help {MONTH}.
			$help {DAY}.
			$help {HOUR}.
			$help {MINUTE}.
			$help {SECOND};

	return $new_date; 

}

################################################################################
##                     OpenCA::OpenSSL::Fast area                             ##
################################################################################

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use OpenCA::OpenSSL::Fast ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	CTX_TEST
	EXFLAG_BCONS
	EXFLAG_CA
	EXFLAG_INVALID
	EXFLAG_KUSAGE
	EXFLAG_NSCERT
	EXFLAG_SET
	EXFLAG_SS
	EXFLAG_V1
	EXFLAG_XKUSAGE
	GEN_DIRNAME
	GEN_DNS
	GEN_EDIPARTY
	GEN_EMAIL
	GEN_IPADD
	GEN_OTHERNAME
	GEN_RID
	GEN_URI
	GEN_X400
	KU_CRL_SIGN
	KU_DATA_ENCIPHERMENT
	KU_DECIPHER_ONLY
	KU_DIGITAL_SIGNATURE
	KU_ENCIPHER_ONLY
	KU_KEY_AGREEMENT
	KU_KEY_CERT_SIGN
	KU_KEY_ENCIPHERMENT
	KU_NON_REPUDIATION
	NS_OBJSIGN
	NS_OBJSIGN_CA
	NS_SMIME
	NS_SMIME_CA
	NS_SSL_CA
	NS_SSL_CLIENT
	NS_SSL_SERVER
	X509V3_EXT_CTX_DEP
	X509V3_EXT_DYNAMIC
	X509V3_EXT_MULTILINE
	X509V3_F_COPY_EMAIL
	X509V3_F_COPY_ISSUER
	X509V3_F_DO_EXT_CONF
	X509V3_F_DO_EXT_I2D
	X509V3_F_HEX_TO_STRING
	X509V3_F_I2S_ASN1_ENUMERATED
	X509V3_F_I2S_ASN1_INTEGER
	X509V3_F_I2V_AUTHORITY_INFO_ACCESS
	X509V3_F_NOTICE_SECTION
	X509V3_F_NREF_NOS
	X509V3_F_POLICY_SECTION
	X509V3_F_R2I_CERTPOL
	X509V3_F_S2I_ASN1_IA5STRING
	X509V3_F_S2I_ASN1_INTEGER
	X509V3_F_S2I_ASN1_OCTET_STRING
	X509V3_F_S2I_ASN1_SKEY_ID
	X509V3_F_S2I_S2I_SKEY_ID
	X509V3_F_STRING_TO_HEX
	X509V3_F_SXNET_ADD_ASC
	X509V3_F_SXNET_ADD_ID_INTEGER
	X509V3_F_SXNET_ADD_ID_ULONG
	X509V3_F_SXNET_GET_ID_ASC
	X509V3_F_SXNET_GET_ID_ULONG
	X509V3_F_V2I_ACCESS_DESCRIPTION
	X509V3_F_V2I_ASN1_BIT_STRING
	X509V3_F_V2I_AUTHORITY_KEYID
	X509V3_F_V2I_BASIC_CONSTRAINTS
	X509V3_F_V2I_CRLD
	X509V3_F_V2I_EXT_KU
	X509V3_F_V2I_GENERAL_NAME
	X509V3_F_V2I_GENERAL_NAMES
	X509V3_F_V3_GENERIC_EXTENSION
	X509V3_F_X509V3_ADD_VALUE
	X509V3_F_X509V3_EXT_ADD
	X509V3_F_X509V3_EXT_ADD_ALIAS
	X509V3_F_X509V3_EXT_CONF
	X509V3_F_X509V3_EXT_I2D
	X509V3_F_X509V3_GET_VALUE_BOOL
	X509V3_F_X509V3_PARSE_LIST
	X509V3_F_X509_PURPOSE_ADD
	X509V3_R_BAD_IP_ADDRESS
	X509V3_R_BAD_OBJECT
	X509V3_R_BN_DEC2BN_ERROR
	X509V3_R_BN_TO_ASN1_INTEGER_ERROR
	X509V3_R_DUPLICATE_ZONE_ID
	X509V3_R_ERROR_CONVERTING_ZONE
	X509V3_R_ERROR_IN_EXTENSION
	X509V3_R_EXPECTED_A_SECTION_NAME
	X509V3_R_EXTENSION_NAME_ERROR
	X509V3_R_EXTENSION_NOT_FOUND
	X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED
	X509V3_R_EXTENSION_VALUE_ERROR
	X509V3_R_ILLEGAL_HEX_DIGIT
	X509V3_R_INVALID_BOOLEAN_STRING
	X509V3_R_INVALID_EXTENSION_STRING
	X509V3_R_INVALID_NAME
	X509V3_R_INVALID_NULL_ARGUMENT
	X509V3_R_INVALID_NULL_NAME
	X509V3_R_INVALID_NULL_VALUE
	X509V3_R_INVALID_NUMBER
	X509V3_R_INVALID_NUMBERS
	X509V3_R_INVALID_OBJECT_IDENTIFIER
	X509V3_R_INVALID_OPTION
	X509V3_R_INVALID_POLICY_IDENTIFIER
	X509V3_R_INVALID_SECTION
	X509V3_R_INVALID_SYNTAX
	X509V3_R_ISSUER_DECODE_ERROR
	X509V3_R_MISSING_VALUE
	X509V3_R_NEED_ORGANIZATION_AND_NUMBERS
	X509V3_R_NO_CONFIG_DATABASE
	X509V3_R_NO_ISSUER_CERTIFICATE
	X509V3_R_NO_ISSUER_DETAILS
	X509V3_R_NO_POLICY_IDENTIFIER
	X509V3_R_NO_PUBLIC_KEY
	X509V3_R_NO_SUBJECT_DETAILS
	X509V3_R_ODD_NUMBER_OF_DIGITS
	X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS
	X509V3_R_UNABLE_TO_GET_ISSUER_KEYID
	X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT
	X509V3_R_UNKNOWN_EXTENSION
	X509V3_R_UNKNOWN_EXTENSION_NAME
	X509V3_R_UNKNOWN_OPTION
	X509V3_R_UNSUPPORTED_OPTION
	X509V3_R_USER_TOO_LONG
	X509_PURPOSE_ANY
	X509_PURPOSE_CRL_SIGN
	X509_PURPOSE_DYNAMIC
	X509_PURPOSE_DYNAMIC_NAME
	X509_PURPOSE_MAX
	X509_PURPOSE_MIN
	X509_PURPOSE_NS_SSL_SERVER
	X509_PURPOSE_SMIME_ENCRYPT
	X509_PURPOSE_SMIME_SIGN
	X509_PURPOSE_SSL_CLIENT
	X509_PURPOSE_SSL_SERVER
	XKU_CODE_SIGN
	XKU_SGC
	XKU_SMIME
	XKU_SSL_CLIENT
	XKU_SSL_SERVER
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	CTX_TEST
	EXFLAG_BCONS
	EXFLAG_CA
	EXFLAG_INVALID
	EXFLAG_KUSAGE
	EXFLAG_NSCERT
	EXFLAG_SET
	EXFLAG_SS
	EXFLAG_V1
	EXFLAG_XKUSAGE
	GEN_DIRNAME
	GEN_DNS
	GEN_EDIPARTY
	GEN_EMAIL
	GEN_IPADD
	GEN_OTHERNAME
	GEN_RID
	GEN_URI
	GEN_X400
	KU_CRL_SIGN
	KU_DATA_ENCIPHERMENT
	KU_DECIPHER_ONLY
	KU_DIGITAL_SIGNATURE
	KU_ENCIPHER_ONLY
	KU_KEY_AGREEMENT
	KU_KEY_CERT_SIGN
	KU_KEY_ENCIPHERMENT
	KU_NON_REPUDIATION
	NS_OBJSIGN
	NS_OBJSIGN_CA
	NS_SMIME
	NS_SMIME_CA
	NS_SSL_CA
	NS_SSL_CLIENT
	NS_SSL_SERVER
	X509V3_EXT_CTX_DEP
	X509V3_EXT_DYNAMIC
	X509V3_EXT_MULTILINE
	X509V3_F_COPY_EMAIL
	X509V3_F_COPY_ISSUER
	X509V3_F_DO_EXT_CONF
	X509V3_F_DO_EXT_I2D
	X509V3_F_HEX_TO_STRING
	X509V3_F_I2S_ASN1_ENUMERATED
	X509V3_F_I2S_ASN1_INTEGER
	X509V3_F_I2V_AUTHORITY_INFO_ACCESS
	X509V3_F_NOTICE_SECTION
	X509V3_F_NREF_NOS
	X509V3_F_POLICY_SECTION
	X509V3_F_R2I_CERTPOL
	X509V3_F_S2I_ASN1_IA5STRING
	X509V3_F_S2I_ASN1_INTEGER
	X509V3_F_S2I_ASN1_OCTET_STRING
	X509V3_F_S2I_ASN1_SKEY_ID
	X509V3_F_S2I_S2I_SKEY_ID
	X509V3_F_STRING_TO_HEX
	X509V3_F_SXNET_ADD_ASC
	X509V3_F_SXNET_ADD_ID_INTEGER
	X509V3_F_SXNET_ADD_ID_ULONG
	X509V3_F_SXNET_GET_ID_ASC
	X509V3_F_SXNET_GET_ID_ULONG
	X509V3_F_V2I_ACCESS_DESCRIPTION
	X509V3_F_V2I_ASN1_BIT_STRING
	X509V3_F_V2I_AUTHORITY_KEYID
	X509V3_F_V2I_BASIC_CONSTRAINTS
	X509V3_F_V2I_CRLD
	X509V3_F_V2I_EXT_KU
	X509V3_F_V2I_GENERAL_NAME
	X509V3_F_V2I_GENERAL_NAMES
	X509V3_F_V3_GENERIC_EXTENSION
	X509V3_F_X509V3_ADD_VALUE
	X509V3_F_X509V3_EXT_ADD
	X509V3_F_X509V3_EXT_ADD_ALIAS
	X509V3_F_X509V3_EXT_CONF
	X509V3_F_X509V3_EXT_I2D
	X509V3_F_X509V3_GET_VALUE_BOOL
	X509V3_F_X509V3_PARSE_LIST
	X509V3_F_X509_PURPOSE_ADD
	X509V3_R_BAD_IP_ADDRESS
	X509V3_R_BAD_OBJECT
	X509V3_R_BN_DEC2BN_ERROR
	X509V3_R_BN_TO_ASN1_INTEGER_ERROR
	X509V3_R_DUPLICATE_ZONE_ID
	X509V3_R_ERROR_CONVERTING_ZONE
	X509V3_R_ERROR_IN_EXTENSION
	X509V3_R_EXPECTED_A_SECTION_NAME
	X509V3_R_EXTENSION_NAME_ERROR
	X509V3_R_EXTENSION_NOT_FOUND
	X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED
	X509V3_R_EXTENSION_VALUE_ERROR
	X509V3_R_ILLEGAL_HEX_DIGIT
	X509V3_R_INVALID_BOOLEAN_STRING
	X509V3_R_INVALID_EXTENSION_STRING
	X509V3_R_INVALID_NAME
	X509V3_R_INVALID_NULL_ARGUMENT
	X509V3_R_INVALID_NULL_NAME
	X509V3_R_INVALID_NULL_VALUE
	X509V3_R_INVALID_NUMBER
	X509V3_R_INVALID_NUMBERS
	X509V3_R_INVALID_OBJECT_IDENTIFIER
	X509V3_R_INVALID_OPTION
	X509V3_R_INVALID_POLICY_IDENTIFIER
	X509V3_R_INVALID_SECTION
	X509V3_R_INVALID_SYNTAX
	X509V3_R_ISSUER_DECODE_ERROR
	X509V3_R_MISSING_VALUE
	X509V3_R_NEED_ORGANIZATION_AND_NUMBERS
	X509V3_R_NO_CONFIG_DATABASE
	X509V3_R_NO_ISSUER_CERTIFICATE
	X509V3_R_NO_ISSUER_DETAILS
	X509V3_R_NO_POLICY_IDENTIFIER
	X509V3_R_NO_PUBLIC_KEY
	X509V3_R_NO_SUBJECT_DETAILS
	X509V3_R_ODD_NUMBER_OF_DIGITS
	X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS
	X509V3_R_UNABLE_TO_GET_ISSUER_KEYID
	X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT
	X509V3_R_UNKNOWN_EXTENSION
	X509V3_R_UNKNOWN_EXTENSION_NAME
	X509V3_R_UNKNOWN_OPTION
	X509V3_R_UNSUPPORTED_OPTION
	X509V3_R_USER_TOO_LONG
	X509_PURPOSE_ANY
	X509_PURPOSE_CRL_SIGN
	X509_PURPOSE_DYNAMIC
	X509_PURPOSE_DYNAMIC_NAME
	X509_PURPOSE_MAX
	X509_PURPOSE_MIN
	X509_PURPOSE_NS_SSL_SERVER
	X509_PURPOSE_SMIME_ENCRYPT
	X509_PURPOSE_SMIME_SIGN
	X509_PURPOSE_SSL_CLIENT
	X509_PURPOSE_SSL_SERVER
	XKU_CODE_SIGN
	XKU_SGC
	XKU_SMIME
	XKU_SSL_CLIENT
	XKU_SSL_SERVER
);

## we take the version from OpenSSL.pm
## our $VERSION = '0.02';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&OpenCA::OpenSSL::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('OpenCA::OpenSSL', $OpenCA::OpenSSL::VERSION);

# Autoload methods go after =cut, and are processed by the autosplit program.

1;

__END__
