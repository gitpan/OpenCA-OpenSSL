## OpenCA::OpenSSL
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
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

package OpenCA::OpenSSL;

$VERSION = '0.4.51';

## Global Variables Go HERE
my %params = (
	 shell => undef,
	 cnf => undef,
	 tmpDir => undef,
	 baseDir => undef,
	 verify => undef,
	 sign => undef,
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
		$self->{binDir} = "/usr/local/ssl/bin";
	};

        if( not $self->{shell} ) {
                $self->{shell} = "$self->{binDir}/openssl";
        };

	if( not $self->{verify} ) {
		$self->{verify} = "$self->{binDir}/verify";
	};

	if( not $self->{sign} ) {
		$self->{sign} = "$self->{binDir}/sign";
	};

	if( not $self->{tmpDir} ) {
		$self->{tmpDir} = '/tmp';
	};

	if( not -e "$self->{shell}" ) {
		return;
	};

        return $self;
}


sub setParams {

	my $self = shift;
	my $params = { @_ };

	foreach $key ( keys %{$params} ) {

		$self->{cnf} = $params->{$key}     if ( $key =~ /CONFIG/ );
		$self->{shell} = $params->{$key}   if ( $key =~ /SHELL/  );
		$self->{tmpDir} = $params->{$key}  if ( $key =~ /TMPDIR/ );
		$self->{binDir} = $params->{$key} if ( $key =~ /BINDIR/ );
		$self->{verify} = $params->{$key}  if ( $key =~ /VERIFY/ );
		$self->{sign} = $params->{$key}  if ( $key =~ /SIGN/ );
		open STDERR, $params->{$key} if ( $key =~ /STDERR/ );
	}

	return 1;
}

sub genKey {

	## Generate a new key, arguments accepted are, in order
	##  ( BITS=>$bits, OUTFILE=>$outfile, ALGORITHM=>$alg, PASSWD=>$passwd )

	my $self = shift;
	my $keys = { @_ };

	my $bits    = $keys->{BITS};
	my $outfile = $keys->{OUTFILE};
	my $alg     = $keys->{ALGORITHM};
	my $passwd  = $keys->{PASSWD};

	my $command = "$self->{shell} genrsa ";

	if ( $alg ne "" ) {
		$command .= "-$alg ";
	}

	if ( $outfile ne "" ) {
		$command .= "-out $outfile ";
	}

	$command .= $bits;

	open(FD, "|$command" ) || return;
		## Send Password
		print FD "$passwd\n";

		## Send Confirmation Password
		print FD "$passwd\n";
	close(FD);

	if( $? != 0 ) {
		return;
	}

	return "$!";
}

sub genReq {

	## Generate a Request file, parameter accepted are
	## ( $outfile, $keyfile, $passwd , [email, cn, ou, o, c ] )
	## To utilize null passwd simply pass a "" reference.

	my $self = shift;
	my $keys = { @_ };

	my $outfile = $keys->{OUTFILE};
	my $outform = $keys->{OUTFORM};
	my $keyfile = $keys->{KEYFILE};
	my $passwd  = $keys->{PASSWD};
	my @DN      = @{ $keys->{DN} };
	my $command = "$self->{shell} req -new ";
	my $tmpfile = $self->{tmpDir} . "/${$}_req.pem";
	my $ret;

	return if( not $keyfile );

	if ( $self->{cnf} ne "" ) {
		$command .= "-config " . $self->{cnf} . " ";
	}

	$outform = uc( $outform );
	if ( $outform =~ /(PEM|DER)/i ) {
		$command .= "-outform $outform ";
	} elsif ( $outform =~ /(TXT)/ ) {
		$command .= "-text -noout ";
	}
	
	if ( $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= " >$tmpfile ";
	}
	
	$command .= "-key $keyfile ";

	open( FD, "|$command" ) or return ;
		if( $passwd ne "" ) {
			print FD "$passwd\n";
		}

		foreach $tmp (@DN) {
			print FD "$tmp\n";
		}

	close(FD);

	if( $? != 0 ) {
		return;
	}

	if( $outfile eq "" ) {
		open( FD, "<$tmpfile" ) || return;
			while( $tmp = <FD> ) {
				$ret .= $tmp;
			}
		close(FD);
		unlink( "$tmpfile" );

		return $ret;
	}

	
	return defined;
}

sub genCert {

	## Generate a new Certificate file, parameter accepted are
	## (OUTFILE=>$outfile,KEYFILE=>$keyfile,REQFILE=>$reqfile,
	## PASSWD=>$passwd, DN=>[ @list ] )

	my $self = shift;
	my $keys = { @_ };
	my $ret = "";

	my $outfile = $keys->{OUTFILE};
	my $keyfile = $keys->{KEYFILE};
	my $reqfile = $keys->{REQFILE};
	my $passwd  = $keys->{PASSWD};
	my $days    = $keys->{DAYS};
	my $tmpfile = $self->{tmpDir} . "/${$}_crt.tmp";

	my $command = "$self->{shell} req -x509 ";

	return if( (not $keyfile) or (not $reqfile) );

	$command .= "-config ". $self->{cnf} . " " if ( $self->{cnf} ne "" );
	$command .= "-days $days " if ( $days > 0 );

	$command .= "-in \"$reqfile\" -key \"$keyfile\" ";

	if( $outfile ne "" ) {
		$command .= "-out \"$outfile\" ";
	} else {
		$command .= "-out \"$tmpfile\" ";
	}

	open( FD, "|$command" ) || return ;
		print FD "$passwd\n";
	close(FD);

	if( $? != 0 ) {
		return;
	}

	if( $outfile eq "" ) {
		open( FD, "<$tmpfile" ) || return;
			while( $tmp = <FD> ) {
				$ret .= $tmp;
			}
		close(FD);
		unlink( "$tmpfile" );
	}

	return "$ret";
}

sub dataConvert {

	## You can convert data structures to different formats
	## Accepted parameters are:
	##
	##    DATATYPE=> CRL|CERTIFICATE|REQUEST
	##    OUTFORM => PEM|DER|NET|TXT
	##    INFORM  => PEM|DER|NET|TXT
	##    OUTFILE => $outfile
	##    INFILE  => $infile
	##    DATA    => $data

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $type    = $keys->{DATATYPE};
	my $outform = $keys->{OUTFORM};
	my $inform  = $keys->{INFORM};
	my $outfile = $keys->{OUTFILE};
	my $infile  = $keys->{INFILE};

	my $ret, $tmpfile;

	return if( not $type);
	return if( (not $data) and (not $infile));

	$outform = "PEM" if( not $outform ); 
	$inform  = "PEM" if( not $inform ); 

	my $command = "$self->{shell} ";

	     if( $type =~ /CRL/i ) {
		$command .= " crl ";
	} elsif ( $type =~ /CERTIFICATE/i ) {
		$command .= " x509 ";
	} elsif ( $type =~ /REQ/i ) {
		$command .= " req ";
	} else {
		## if no known type is given...
		return;
	}

	$command .= "-out $outfile " if ( $outfile ne "" ); 
	$command .= "-in $infile " if ( $infile ne "" ); 

	     if( $outform =~ /TXT/i ) {
		$command .= "-text -noout ";
	} elsif ( $outform =~ /(PEM|DER|NET)/i ) {
		$command .= "-outform " . uc($outform) . " ";
	} else {
		## no valid format received...
		return;
	}
		
	if( $inform =~ /(PEM|DER|NET)/i ) {
		$command .= "-inform " . uc($inform) ." ";
	} else {
		## no valid format received ...
		return;
	}

	if( $infile ne "" ) {
		$ret=`$command`;
		## return if ( $? != 0 );
	} else {
		if( $outfile eq "" ) {
			$tmpfile = $self->{tmpDir} . "/${$}_cnv.tmp";
			$command .= " -out $tmpfile";
		} else {
			$tmpfile = $outfile;
		}

		open( FD, "|$command" ) or return;
			print FD "$data";
		close(FD);

		## return if( $? != 0 );

		open( TMP, "$tmpfile" ) or return;
			my $tmp;
			$ret = "";

			while( $tmp = <TMP> ) {
				$ret .= $tmp;
			}
		close(TMP);
		unlink( $tmpfile );
	}

	return "$ret";

}

sub issueCert {

	## Use this function to issue a certificate using the
	## ca utility. Use this if you already own a valid CA
	## certificate. Accepted parameters are:

	## REQDATA => $data
	## REQFILE => $reqfilename
	## INFORM  => PEM|DER|NET|SPKAC   ; defaults to PEM
	## PRESERVE_DN => Y/N		  ; defaults to Y/N
	## CAKEY   => $CAkeyfile
	## CACERT  => $CAcertfile
	## DAYS    => $days
	## PASSWD  => $passwd
	## EXTS    => $extentions
	## REQTYPE => NETSCAPE|MSIE

	my $self = shift;
	my $keys = { @_ };

	my $reqdata  = $keys->{REQDATA};
	my $reqfile  = $keys->{REQFILE};
	my $inform   = $keys->{INFORM};
	my $preserve = $keys->{PRESERVE_DN};
	my $cakey    = $keys->{CAKEY};
	my $cacert   = $keys->{CACERT};
	my $days     = $keys->{DAYS};
	my $starDate = $keys->{START_DATE};
	my $endDate  = $keys->{END_DATE};
	my $passwd   = $keys->{PASSWD};
	my $exts     = $keys->{EXTS};
	my $reqtype  = $keys->{REQTYPE};
	my $caName   = $keys->{CA_NAME};
	
	my $ret, $tmpfile;

	return if( (not $reqdata) and (not $reqfile));

	$inform   = "PEM" if( not $inform ); 
	$reqtype  = "NETSCAPE" if( not $reqtype ); 

	my $command = "$self->{shell} ca -batch ";

	$command .= "-config " .$self->{cnf}." " if ( $self->{cnf} );
	$command .= "-keyfile $cakey " if( $cakey );
	$command .= "-key $passwd " if ( $passwd );
	$command .= "-days $days " if ( $days );
	$command .= "-extensions $exts " if ( $exts );
	$command .= "-preserveDN " if ( $preserve =~ /Y/i );
	$command .= "-startdate $startDate " if ( $startDate );
	$command .= "-enddate $endDate " if ( $endDate );
	$command .= "-name $caName " if ( $caName );

	     if( $inform =~ /(PEM|DER|NET)/i ) {
		$command .= "-inform " . uc($inform) ." ";
		$command .= "-in $reqfile " if ( $reqfile );
	} elsif ( $inform =~ /SPKAC/ ) {
		return if ( not $reqfile );
		$command .= "-spkac $reqfile ";
	} else {
		## no valid format received ...
		return;
	}

	if ( $reqtype =~ /MSIE/i ) {
		$command .= "-msie_hack ";
	} elsif ($reqtype =~ /NETSCAPE/i ) {
		## Nothing to do...
	} else {
		return;
	}

	if( $reqfile ne "" ) {
		$ret = `$command`;
		return if( $? != 0);
	} else {
		open( FD, "|$command" ) || return;
			print "$reqdata";
		close(FD);

		return if( $? != 0);
	}

	return 1;
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
	my $cacert   = $keys->{CACERT};
	my $days     = $keys->{DAYS};
	my $passwd   = $keys->{PASSWD};
	my $outfile  = $keys->{OUTFILE};
	my $outform  = $keys->{OUTFORM};
	my $exts     = $keys->{EXTS};
	
	my $ret;
	my $command = "$self->{shell} ca -gencrl ";

	if ( $outfile eq "" ){
		$tmpfile = $self->{tmpDir} . "/${$}_crl.tmp";
		$command .= "-out $tmpfile ";
	} else {
		$command .= "-out $outfile ";
	}

	$command .= "-config " . $self->{cnf}. " " if ( $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( $cakey ne "" );
	$command .= "-key $passwd " if ( $passwd ne "" );
	$command .= "-cert $cacert " if ( $cacert ne "" );
	$command .= "-crldays $days " if ( $days ne "" );
	$command .= "-crlexts $exts " if ( $exts ne "" );

	open( FD, "|$command" ) || return;
	close(FD);

	return if( $? != 0);

##	if( $outform =~ /(DER|NET|TXT|PEM)/i ) {
		my $tmp;

		if ( $outfile ne "" ) {
			$tmp = $outfile;
		} else {
			$tmp = $tmpfile;
		}

		$ret = $self->dataConvert( INFILE  =>$tmp,
					   OUTFORM =>$outform,
					   DATATYPE=>CRL );
		return if( not $ret );


		if( $outfile ne "" ) {
			open( FD, ">$outfile" ) or return;
				print FD "$ret";
			close(FD);
			return 1;
		} else {
			unlink( $tmp );
			return "$ret";
		}
##	} else {
##		if( $outfile eq "" ) {
##			open( FD, "<$tmp" ) or return;
##				my $tmp;
##				$ret = "";
##
##				while ( $tmp = <FD> ) {
##					$ret .= "$tmp";
##				}
##			close(FD);
##			unlink( $tmp );
##
##			return $ret;
##		}
##	}

	return 1;
		
}

sub SPKAC {

	my $self = shift;
	my $keys = { @_ };

	my $infile  = $keys->{INFILE};
	my $outfile = $keys->{OUTFILE};
	my $spkac   = $keys->{SPKAC};

	my $command = "$self->{shell} spkac -verify ";
	my $tmpfile = $self->{tmpDir} . "/${$}_SPKAC.tmp";
	my $ret;

	$command .= "-in $infile " if( $infile ne "" );
	$command .= "-out $outfile " if( $outfile ne "" );

	if( $infile ne "" ) {
		my $tmp;

		open( FD, "$command|" ) or return;
			while( $tmp = <FD> ) {
				$ret .= $tmp;
			}
		close(FD);

		return if ( $? != 0 );

	} else {
		$command .= ">$tmpfile " if ( $outfile eq "" );

		open( FD, "|$command" ) or return;
			print FD "$spkac";
		close(FD);

		if( $? != 0 ) {
			unlink( $tmpfile ) if( $outfile eq "" );
			return;
		}

		open( TMP, "$tmpfile" ) or return;
			my $tmp;
			$ret = "";

			while ( $tmp = <TMP> ) {
				$ret .= $tmp;
			};
		close(TMP);
	}

	unlink( $tmpfile ) if( $outfile eq "" );
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

	$alg = "md5" if( not $alg );

	return if (not $data);
	open( FD, ">$tmpfile" ) or return;
	 	print FD $data;
	close( FD );

	$command = "$self->{shell} dgst -$alg <\"$tmpfile\"";
	
	$ret = `$command`;
	$ret =~ s/\n//g;

	unlink( $tmpfile );

	if( $? != 0 ) {
		return;
	} else {
		return $ret;
	}
}

sub verify {

	## Verify PKCS7 signatures (new OpenCA::verify command
	## should be used )

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA_FILE};
	my $sig     = $keys->{SIGNATURE};
	my $sigfile = $keys->{SIGNATURE_FILE};
	my $cacert  = $keys->{CA_CERT};
	my $cadir   = $keys->{CA_DIR};
	my $verbose = $keys->{VERBOSE};
	my $out	    = $keys->{OUTFILE};
	my $noChain = $keys->{NOCHAIN};
	my $tmpfile = $self->{tmpDir} . "/${$}_vrfy.tmp";
	my $command = $self->{verify} . " ";

	$command   .= "-verbose " if ( $verbose );
	$command   .= "-in $sigfile " if ($sigfile);
	$command   .= "-cf $cacert " if ( $cacert );
	$command   .= "-cd $cadir " if ($cadir);
	$command   .= "-data $data " if ($data);
	$command   .= "-out $out" if ( $out );
	$command   .= "-no_chain $out" if ( $noChain );

	if( $sigfile ) {
		$ret=`$command`;
	} else {
		if( not $out ) {
			$command .= " >$tmpfile";
		}

		open( FD, "|$command" ) or return;
			print FD "$sig";
		close(FD);

		if ( $? ) {
			unlink( $tmpfile ) if (not $out);
			return;
		}

		if( not $out) {
			$ret = "";
			open( TMP, "<$tmpfile" ) or return;
				do {
					$ret .= <TMP>;
				} while (not eof(TMP));
			close(TMP);

			unlink( $tmpfile );
		}
	}

	## If we are here there have been no errors, so
	## if $ret is empty, let's return a true value...
	$ret = 1 if ( not $ret );

	return $ret;
}

sub sign {

	## Generate a PKCS7 signature.

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	my $out     = $keys->{OUT_FILE};
	my $cert    = $keys->{CERT_FILE};
	my $key     = $keys->{KEY_FILE};
	my $nonDetach = $keys->{INCLUDE_DATA};
	my $pwd     = $keys->{PWD};
	my $tmpfile = $self->{tmpDir} . "/${$}_sign.tmp";
	my $command = $self->{sign} . " ";

	return if( (not $data) and (not $datafile));
	return if( (not $cert) or (not $key));

	$command   .= "-in $datafile " if ($datafile);
	$command   .= "-out $out " if ( $out );
	$command   .= "-key $key " if ( $pwd );
	$command   .= "-nd " if ( $nonDetach );

	$command   .= "-cert $cert -keyfile $key ";

	if( $datafile ) {
		$ret=`$command`;
		if( $? ) {
			return;
		};
	} else {
		if( not $out) {
			$command .= " >$tmpfile";
		};

		open( FD, "|$command" ) or return;
			print FD "$data";
		close(FD);

		if ( $? ) {
			unlink( $tmpfile ) if (not $out);
			return;
		}

		if( not $out ) {
			open( TMP, "<$tmpfile" ) or return;
				do {
					$ret .= <TMP>;
				} while (not eof($ret));
			close(TMP);

			unlink( $tmpfile );
		}
	}

	## If we are here there have been no errors, so
	## if $ret is empty, let's return a true value...
	$ret = 1 if ( not $ret );

	return $ret;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::OpenSSL - Perl Crypto Extention to OpenSSL

=head1 SYNOPSIS

  use OpenCA::OpenSSL;

=head1 DESCRIPTION

This Perl Module implements an interface to the openssl backend
program. It actually uses the openssl command and it is not fully
integrated as PERL/C mixture.

Passing parameters to functions should be very simple as them have
no particular order and have, often, self-explaining name. Each
parameter should be passed to the function like this:

	... ( NAME=>VALUE, NAME=>VALUE, ... );

=head1 FUNCTIONS

=head2 sub new () - Creates a new Class instance.

	This functions creates a new instance of the class. It accepts
	only one parameter: the path to the backend command (openssl).

	EXAMPLE:

		my $openssl->new OpenCA::OpenSSL( $path );

=head2 sub setParams () - Set internal module variables.

	This function can handle the internal module data such as the
	backend path or the tmp dir. Accepted parameters are:

		SHELL   - Path to the openssl command.
		CONFIG  - Path to the openssl config file.
		TMPDIR  - Temporary files directory.
		STDERR  - Where to redirect the STDERR file.

	(*) - Optional parameters;

	EXAMPLE:

		$openssl->setParams( SHELL=>'/usr/local/ssl/bin/openssl',
				     CONFIG=>$ca/stuff/openssl.cnf,
				     TMPDIR=>'/tmp',
				     STDERR=>'/dev/null' );

=head2 sub genKey () - Generate a private Key.

	This functions let you generate a new private key. Accepted
	parameters are:

		BITS      - key lengh in bits(*);
		OUTFILE   - Output file name(*);
		ALGORITHM - Encryption Algorithm to be used(*);
		PASSWD    - Password to be used when encrypting(*);

	(*) - Optional parameters;

	EXAMPLE:

		my $key = $openssl->genKey( BITS=>1024 );

=head2 sub genReq () - Generate a new Request.

	This function generate a new certificate request. Accepted
	parameters are:

		OUTFILE  - Output file(*);
		KEYFILE  - File containing the key;
		PASSWD   - Password to decript key (if needed) (*);
		DN       - Subject list (as required by openssl, see
			   the openssl.cnf doc on policy);

	(*) - Optional parameters;

	EXAMPLE:

		my $req = $openssl->genReq( KEYFILE=>"00_key.pem",
			DN => [ "madwolf@openca.org","Max","","","" ] );


=head2 sub genCert () - Generate a certificate from a request.

	This function let you generate a new certificate starting
	from the request file. It is used for self-signed certificate
	as it simply converts the request into a x509 structure.
	Accepted parameters are:

		OUTFILE   - Output file(*);
		KEYFILE   - File containing the private key;
		REQFILE   - Request File;
		PASSWD    - Password to decrypt private key(*);
		DAYS      - Validity days(*);

	(*) - Optional parameters;

	EXAMPLE:

		$cert = $openssl->genCert( KEYFILE=>"priv_key.pem",
			REQFILE=>"req.pem",
			DAYS=>"720" );

=head2 sub dataConvert () - Convert data to different format.

	This functions will convert data you pass to another format. Ir
	requires you to provide with the data's type and IN/OUT format.
	Accepted parameters are:

		DATA    - Data to be processed;
		INFILE  - Data file to be processed (one of DATA and
		  	  INFILE are required and exclusive);
		DATATYPE - Data type ( CRL | CERTIFICATE | REQUEST );
		OUTFORM  - Output format (PEM|DER|NET|TXT)(*);
		INFORM   - Input format (PEM|DER|NET|TXT)(*);
		OUTFILE  - Output file(*);

	(*) - Optional parameters;

	EXAMPLE:

		print $openssl->dataConvert( INFILE=>"crl.pem",
			OUTFORM=>"TXT" );

=head2 sub  issueCert () - Issue a certificate.

	This function should be used when you have a CA certificate and
	a request (either DER|PEM|SPKAC) and want to issue the certificate.
	Parameters used will override the configuration values (remember
	to set to appropriate value the CONFIG with the setParams func).
	Accepted parameters are:

		REQDATA       - Request;
		REQFILE       - File containing the request (one of
				REQDATA and REQFILE are required);
		INFORM        - Input format (PEM|DER|NET|SPKAC)(*);
		PRESERVE_DN   - Preserve DN order (Y|N)(*);
		CA_NAME	      - CA sub section to be used (take a
				look at the OpenSSL docs for adding
				support of multiple CAs to the conf
				file)(*);
		CAKEY	      - CA key file;
		CACERT	      - CA certificate file;
		DAYS	      - Days the certificate will be valid(*);
		START_DATE    - Starting validity date (YYMMDDHHMMSSZ)(*);
		END_DATE      - Ending validity date (YYMMDDHHMMSSZ)(*);
		PASSWD	      - Password to decrypt priv. CA key(*);
		EXTS	      - Extentions to be used (configuration
				section of the openssl.cnf file)(*);
		REQTYPE	      - Request type (NETSCAPE|MSIE)(*);

	(*) - Optional parameters;

	EXAMPLE:

		$openssl->issueCert( REQFILE=>"myreq",
			INFORM=>SPKAC,
			PRESERVE_DN=>Y,
			CAKEY=>$ca/private/cakey.pem,
			CACERT=>$ca/cacert.pem,
			PASSWD=>$passwd,
			REQTYPE=>NETSCAPE );

=head2 sub issueCrl () - Issue a CRL.

	This function is used to issue a CRL. Accepted parameters
	are:

		CAKEY   - CA private key file;
		CACERT  - CA certificate file;
		PASSWD  - Password to decrypt priv. CA key(*);
		DAYS    - Days the CRL will be valid for(*);
		EXTS    - Extentions to be added ( see the openssl.cnf
			  pages for more help on this )(*);
		OUTFILE - Output file(*);
		OUTFORM - Output format (PEM|DER|NET|TXT)(*);

	(*) - Optional parameters;

	EXAMPLE:

		print $openssl->issueCrl( CAKEY=>"$ca/private/cakey.pem",
					  CACERT=>"$ca/cacert.pem",
					  DAYS=>7,
					  OUTFORM=>TXT );

=head2 sub SPKAC () - Get SPKAC infos.

	This function returns a text containing all major info
	about an spkac structure. Accepted parameters are:

		SPKAC     - spkac data ( SPKAC = .... ) (*);
		INFILE	  - An spkac request file (*);
		OUTFILE   - Output file (*);
		
	(*) - Optional parameters;

	EXAMPLE:

		print $openssl->SPKAC( SPKAC=>$data, OUTFILE=>$target );

=head2 sub getDigest () - Get a message digest.

	This function returns a message digest. Default digest
	algorithm used is MD5. Accepted parameters are:

		DATA      - Data on which to perform digest;
		ALGORITHM - Algorithm to be used(*);
		
	(*) - Optional parameters;

	EXAMPLE:

		print $openssl->getDigest( DATA=>$data,
					   ALGORITHM=>sha1);

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::X509, OpenCA::CRL, OpenCA::REQ, OpenCA::TRIStateCGI,
OpenCA::Configuration

=cut

