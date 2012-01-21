# ===========================================================================
# Module::Crypt
# 
# Encrypt your Perl code and compile it into XS
# 
# Author: Alessandro Ranellucci <aar@cpan.org>
# Copyright (c).
# 
# This is EXPERIMENTAL code. Use it AT YOUR OWN RISK.
# See below for documentation.
# 

package Module::Crypt;

use strict;
use warnings;
our $VERSION = 0.05;

use Carp qw[croak];
use ExtUtils::CBuilder ();
use ExtUtils::ParseXS ();
use ExtUtils::Mkbootstrap;
use File::Copy 'move';
use File::Find ();
use File::Path ();
use File::Spec ();
use File::Temp 'mktemp';
use IO::File;

require Exporter;
our @ISA = qw[Exporter];
our @EXPORT = qw[CryptModule];

use XSLoader;
XSLoader::load 'Module::Crypt', $VERSION;

our @ToDelete;

sub CryptModule {
	my %Params = @_;
	
	# get modules list
	my @Files;
	if ($Params{file}) {
		push @Files, $Params{file};
	}
	if (ref $Params{files} eq 'ARRAY') {
		push @Files, @{$Params{files}};
	} elsif ($Params{files} && !ref $Params{files}) {
		$Params{files} = File::Spec->rel2abs($Params{files});
		if (-d $Params{files}) {
			# scan directory
			File::Find::find({wanted => sub { 
				push @Files, $File::Find::name if $File::Find::name =~ /\.pm$/;
			}, no_chdir => 1}, $Params{files});
		} elsif (-f $Params{files}) {
			push @Files, $Params{file};
		}
	}
	my (%Modules, $package, $version);
	foreach my $file (@Files) {
		$file = File::Spec->rel2abs($file);
		croak("File $file does not exist") unless -e $file;
		$package = '';
		$version = '1.00';
		open(MOD, "<$file");
		while (<MOD>) {
			if (/^\s*package\s+([a-zA-Z0-9]+(?:::[a-zA-Z0-9_]+)*)\s*/) {
				$package = $1;
			}
			if (/^\s*(?:our\s+)?\$VERSION\s*=\s*['"]?([0-9a-z\.]+)['"]?\s*;/) {
				$version = $1;
			}
		}
		close MOD;
		croak("Failed to parse package name in $file") unless $package;
		croak("File $file conflicts with $Modules{$package}->{file} (package name: $package)")
			if $Modules{$package};
		$Modules{$package} = {file => $file, version => $version};
	}
	
	# let's make sure install_base exists
	$Params{install_base} ||= 'output';
	$Params{install_base} = File::Spec->rel2abs($Params{install_base});
	File::Path::mkpath($Params{install_base});
	
	# create temp directory
	my $TempDir = mktemp( File::Spec->catdir($Params{install_base}, "/tmp.XXXXXXXXX") );
	File::Path::mkpath($TempDir);
	push @ToDelete, $TempDir;
	
	# compile modules
	my $cbuilder = ExtUtils::CBuilder->new;
	
	foreach my $module (keys %Modules) {
	
		my @module_path = _module_path($module);
		my $module_basename = pop @module_path;
	
		# let's create path
		File::Path::mkpath( File::Spec->catdir($TempDir, @module_path) );
		
		# let's write source files
		my $newpath = File::Spec->catfile($TempDir, @module_path, "$module_basename");
		_write_c($module, $Modules{$module}->{version}, $Modules{$module}->{file}, $newpath);
		
		# .xs -> .c
		ExtUtils::ParseXS::process_file(
			filename => "$newpath.xs",
			prototypes => 0,
			output => "$newpath.c",
		);
		
		# .c -> .o
		my $obj_file = $cbuilder->object_file("$newpath.c");
		$cbuilder->compile(
			source => "$newpath.c",
			object_file => $obj_file
		);
		
		# .xs -> .bs
		ExtUtils::Mkbootstrap::Mkbootstrap($newpath);
		{my $fh = IO::File->new(">> $newpath.bs")};  # create
		
		# .o -> .(a|bundle)
		my $lib_file = $cbuilder->lib_file($obj_file);
		print "--> $lib_file\n";
		$cbuilder->link(
			module_name => $module,
	   		objects => [$obj_file],
			lib_file => $lib_file
		);
		
		# move everything to install_base
		my $final_path = File::Spec->catdir($Params{install_base}, @module_path);
		my $final_path_auto = File::Spec->catdir($Params{install_base}, "auto", @module_path, $module_basename);
		File::Path::mkpath($final_path);
		File::Path::mkpath($final_path_auto);
		move("${newpath}.pm", "${final_path}/${module_basename}.pm") or die $!;
		foreach (qw[bs a bundle so]) {
			next unless -e "$newpath.$_";
			move("${newpath}.$_", "${final_path_auto}/") or die $!;
		}
	}		

 	_cleanup();
	return 1;
}

sub _module_path {
	my ($package) = @_;
	return split(/::/, $package);
}

sub END {
	_cleanup();
}

sub _cleanup {
	File::Path::rmtree($_) foreach @ToDelete;
}

sub _write_c {
	my ($package, $version, $pm, $newpath) = @_;
	
	# get source script
	open(SRC, "<$pm");
	my @lines = <SRC>;
	close SRC;
	
	
	# encrypt things
	open(XS, ">$newpath.xs");
	print XS wr(join "", @lines);
	print XS <<"EOF"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <EXTERN.h>
#include <perl.h>
#include <stdlib.h>

/**
 * 'Alleged RC4' Source Code picked up from the news.
 * From: allen\@gateway.grumman.com (John L. Allen)
 * Newsgroups: comp.lang.c
 * Subject: Shrink this C code for fame and fun
 * Date: 21 May 1996 10:49:37 -0400
 */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte. 
 */
void stte_0(void)
{
	indx = jndx = kndx = 0;
	do {
		stte[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once. 
 */
void key(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = stte[indx];
			kndx += tmp;
			kndx += ptr[(int)indx % len];
			stte[indx] = stte[kndx];
			stte[kndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Crypt data. 
 */
void arc4(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		indx++;
		tmp = stte[indx];
		jndx += tmp;
		stte[indx] = stte[jndx];
		stte[jndx] = tmp;
		tmp += stte[indx];
		*ptr ^= stte[tmp];
		ptr++;
		len--;
	}
}

MODULE = $package		PACKAGE = $package

BOOT:
	stte_0();
	 key(pswd, pswd_z);
	arc4(text, text_z);
	eval_pv(text, G_SCALAR);

EOF
	;
	close XS;
	
	open(PM, ">$newpath.pm");
	print PM <<"EOF"
package $package;

use strict;
use warnings;

our \$VERSION = $version;

use XSLoader;
XSLoader::load __PACKAGE__, \$VERSION;

1;

EOF
	;
	close PM;
}

1;

__END__

=head1 NAME

Module::Crypt - Encrypt your Perl code and compile it into XS

=head1 SYNOPSIS

 use Module::Crypt;
 
 # for a single file:
 CryptModule(
    file => 'Bar.pm',
    install_base => '/path/to/my/lib'
 );
 
 # for multiple files:
 CryptModule(
    files => ['Foo.pm', 'Bar.pm'],
    install_base => '/path/to/my/lib'
 );
 
 # for a directory:
 CryptModule(
    files => '/path/to/source/dir',
    install_base => '/path/to/my/lib'
 );


=head1 ABSTRACT

Module::Crypt encrypts your pure-Perl modules and then compiles them
into a XS module. It lets you distribute binary versions without
disclosing code, although please note that we should better call this
an obfuscation, as Perl is still internally working with your original
code. While this isn't 100% safe, it makes code retrival much harder than
any other known Perl obfuscation method.

=head1 PUBLIC FUNCTIONS

=over 4

=item C<CryptModule>

This function does the actual encryption and compilation. It is supposed
to be called from a Makefile-like script that you'll create inside your development
directory. The 4 lines you see in each of the examples above are sufficient to build 
(and rebuild) the modules.

=over 8

=item file

This contains the path of your source module. It can be a relative filename too,
if you're launching your CryptModule() from the same directory.

=item files

If you want to encrypt and compile multiple modules, you can pass an arrayref to the
I<files> parameter with the paths/filenames listed. If you pass a string instead of
of an arrayref, it will be interpreted as a directory path so that Module::Crypt will
scan it and automatically add any .pm file to the modules list.

=item install_base

(Optional) This parameter contains the destination of the compiled modules. If not
specified, it defaults to a directory named "output" inside the current working directory.

=back

=back

=head1 BUGS

=over 4

=item

There could be some malloc() errors and/or segmentation faults when encrypting 
long scripts. Try running your script multiple times as it's a random error. 
It should be very easy to fix (the cause is bad way to calculate allocation needs).

=back

=head1 AVAILABILITY

Latest versions can be downloaded from CPAN. You are very welcome to write mail 
to the author (aar@cpan.org) with your contributions, comments, suggestions, 
bug reports or complaints.

=head1 AUTHOR

Alessandro Ranellucci E<lt>aar@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) Alessandro Ranellucci.
Module::Crypt is free software, you may redistribute it and/or modify it under 
the same terms as Perl itself.

=head1 DISCLAIMER

This is highly experimental code. Use it AT YOUR OWN RISK. 
This software is provided by the copyright holders and contributors ``as
is'' and any express or implied warranties, including, but not limited to,
the implied warranties of merchantability and fitness for a particular
purpose are disclaimed. In no event shall the regents or contributors be
liable for any direct, indirect, incidental, special, exemplary, or
consequential damages (including, but not limited to, procurement of
substitute goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether in
contract, strict liability, or tort (including negligence or otherwise)
arising in any way out of the use of this software, even if advised of the
possibility of such damage.

=cut