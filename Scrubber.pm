package Log::Scrubber;

=head1 NAME

Log::Scrubber - Perl extension to avoid logging sensitive data

=cut

require 5.005;
use strict;
use warnings;
use Carp;
no warnings "redefine"; # We make this a few times
use Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $SCRUBBER);

@ISA = qw(Exporter);
%EXPORT_TAGS = (
    Carp    => [ qw(scrubber_init carp croak confess cluck) ],
    Syslog  => [ qw(scrubber_init syslog) ],
    all     => [ qw($SCRUBBER scrubber_init scrubber scrubber_enabled) ],
    );

push @{$EXPORT_TAGS{all}}, @{$EXPORT_TAGS{$_}} 
for grep { $_ ne 'all' } keys %EXPORT_TAGS;

@EXPORT_OK = @{$EXPORT_TAGS{all}}; 
@EXPORT = qw(scrubber_init);

$VERSION = '0.02';

###----------------------------------------------------------------###

my $_SDATA = {
    'enabled' => 1,
    'SIG' => {},
    'METHOD' => {},
};
tie $SCRUBBER, __PACKAGE__;

sub TIESCALAR {
    return bless [], __PACKAGE__;
}

sub FETCH {
    my ($self) = @_;
    $_SDATA;
}

sub STORE {
    my ($self, $val) = @_;
    #print ">>>>Calling STORE with (".(defined($val) ? $val : 'undef').")\n";
    if (! defined $val) {
        my $old_sdata = $_SDATA;
        $_SDATA = {};
        foreach my $key ( 'scrub_data', 'SIG', 'METHOD' ) {
            # make a non-reference copy, so when we go out of scope we get the old values
            %{$_SDATA->{$key}} = %{$old_sdata->{$key}} if defined $old_sdata->{$key};
        }
        $_SDATA->{'enabled'} = $old_sdata->{'enabled'};
    } elsif (ref($val) eq 'HASH') {
        scrubber_stop();
        $_SDATA = $val;
        scrubber_start() if $_SDATA->{'enabled'};
    } elsif ($val) {
        scrubber_start();
    } else {
        scrubber_stop();
    }
}

###----------------------------------------------------------------###

sub import {
    my $change;
    for my $i (reverse 1 .. $#_) {
        next if $_[$i] !~ /^(dis|en)able$/;
        my $val = $1 eq 'dis' ? 0 : 1;
        splice @_, $i, 1, ();
        die 'Cannot both enable and disable $SCRUBBER during import' if defined $change && $change != $val;
        $SCRUBBER = $val;
    }
    __PACKAGE__->export_to_level(1, @_);
}

###----------------------------------------------------------------###

sub scrubber_enabled { $_SDATA->{'enabled'} ? 1 : 0 }

sub scrubber_start {
    $_SDATA->{'enabled'} = 1;
    scrubber_enable_signal( keys $_SDATA->{'SIG'} );
    scrubber_enable_method( keys $_SDATA->{'METHOD'} );
}

sub scrubber_stop  {
    $_SDATA->{'enabled'} = 0;
    scrubber_disable_signal( keys $_SDATA->{'SIG'} );
    scrubber_disable_method( keys $_SDATA->{'METHOD'} );
}

=pod

=head1 SYNOPSIS

  use Log::Scrubber;             # Override warn() and die() and import scrubber_init()
  use Log::Scrubber qw(:all);    # Override eveything this module knows
  use Log::Scrubber qw(:Carp);   # Only override Carp:: methods
  use Log::Scrubber qw(:Syslog); # Only override syslog()
  use Log::Scrubber qw(scrubber);   # scrubber() for use on your own

  use Log::Scrubber qw(:Syslog :Carp); # Or combine a few

  Example:

    scrubber_init( { '4007000000027' => 'DELETED' } );
    warn "The card number is 4007000000027.\n";

  Output:

    The card number is DELETED.
  
=head1 DESCRIPTION

As required by the PCI Security Standads Counsil, some data is not
acceptable to send to log files.  Most notably CVV data.  However it
is simply a matter of time before a developer accidentally (or on purpose)
logs sensitive data to the error_log, or some other innapropriate location.

This module is a quick solution for this vulnerability. What it does
is very simple: It replaces ocurrences of the your sensitive data in the
output of any common logging mechanism such as C<use warnings>,
C<warn>, C<use Carp> and C<die> with an acceptable alternative provided
by you.

It does so by overriding the functions with a safer alternative so
that no code needs to be changed.

Note that in order for this protection to be effective, this module
must be C<use>d as the last module (ie, after all the modules it can
override) in order for proper method replacement to occur.

The protection can also be invoked by the C<scrubber> method, which
takes a list of arguments and returns the same list, with all ESC
characters safely replaced. This method is provided so that you can
call it by yourself.

Typically, you will want to issue an C<use Log::Scrubber qw(:all)> after
the last module is C<use>d in your code, to automatically benefit from
the most common level of protection.

Note: If your using your own $SIG{__WARN__} and $SIG{__DIE__} then you
must call scrubber_ini() afterward to maintain full protection.

=cut

###----------------------------------------------------------------###
# This is the core of our protection. Replace
# the data by the value provided

sub _scrubber {
    my $msg = $_[0];
    return $_[0] if ref $_[0];
    foreach ( keys %{$_SDATA->{'scrub_data'}}) {
        $msg =~ s/$_/$_SDATA->{'scrub_data'}{$_}/g;
    }
    return $msg;
}

sub scrubber {
    return map { _scrubber $_ } @_;
}

###----------------------------------------------------------------###

=pod

=over

=item C<warn>

The standard Perl C<warn()>.

=cut

my $_scrubber_warn = sub {
    @_ = scrubber @_;
    defined $_SDATA->{'SIG'}{'WARN'} ? $_SDATA->{'SIG'}{'WARN'}->(@_) : CORE::warn(@_);
};

=pod

=item C<die>

The standard Perl C<die()>.

=cut

my $_scrubber_die = sub {
    @_ = scrubber @_;
    defined $_SDATA->{'SIG'}{'DIE'} ? $_SDATA->{'SIG'}{'DIE'}->(@_) : CORE::die(@_);
};

###----------------------------------------------------------------###
# Add/Remove text values that will be scrubbed

sub scrubber_remove_scrubber {
    my $x = $_[0];
    if (defined $x) {
        foreach ( keys %$x ) {
            delete $_SDATA->{'scrub_data'}{$_} if $_SDATA->{'scrub_data'}{$_} = $x->{$_};
        }
    }
}

sub scrubber_add_scrubber {
    my $x = $_[0];
    if (defined $x) {
        foreach ( keys %$x ) { $_SDATA->{'scrub_data'}{$_} = $x->{$_}; }
    }
}

###----------------------------------------------------------------###
# Add/Remove signals (ie DIE and WARN) to the scrubber

sub scrubber_disable_signal {
    foreach ( @_ ) {
        if ($_ eq 'WARN') {
            $SIG{__WARN__} = $_SDATA->{'SIG'}{$_};
        }
        if ($_ eq 'DIE') {
            $SIG{__DIE__} = $_SDATA->{'SIG'}{$_};
        }
    }
}

sub scrubber_remove_signal {
    scrubber_disable_signal(@_);
    foreach ( @_ ) {
        delete $_SDATA->{'SIG'}{$_};
    }
}

sub scrubber_enable_signal {
    return if ! $_SDATA->{'enabled'};
    foreach ( @_ ) {
        if ($_ eq 'WARN') {
            $SIG{__WARN__} = $_scrubber_warn;
        }
        if ($_ eq 'DIE') {
            $SIG{__DIE__} = $_scrubber_die;
        }
    }
}

sub scrubber_add_signal {
    foreach ( @_ ) {
        if ($_ eq 'WARN') {
            next if defined $SIG{__WARN__} && $SIG{__WARN__} eq $_scrubber_warn;
            $_SDATA->{'SIG'}{$_} = $SIG{__WARN__};
        }
        if ($_ eq 'DIE') {
            next if defined $SIG{__DIE__} && $SIG{__DIE__} eq $_scrubber_die;
            $_SDATA->{'SIG'}{$_} = $SIG{__DIE__};
        }
    }
    scrubber_enable_signal(@_);
}

###----------------------------------------------------------------###
# Add/Remove methods to the scrubber

sub scrubber_disable_method {
    no strict 'refs';
    foreach my $fullname ( @_ ) {
        my $basename = $fullname;
        $basename =~ s/^.*:://;
        *$basename = $_SDATA->{'METHOD'}{$fullname};
    }
}

sub scrubber_remove_method {
    scrubber_disable_method(@_);
    no strict 'refs';
    foreach my $fullname ( @_ ) {
        my $basename = $fullname;
        $basename =~ s/^.*:://;
	delete $_SDATA->{'METHOD'}{$fullname};
    }
}

sub scrubber_enable_method {
    return if ! $_SDATA->{'enabled'};
    no strict 'refs';
    foreach my $fullname ( @_ ) {
        my $r_orig = $_SDATA->{'METHOD'}{$fullname};
        my $basename = $fullname;
        $basename =~ s/^.*:://;
        *$basename = sub { $r_orig->( scrubber @_ ) };
    }
}

sub scrubber_add_method {
    no strict 'refs';
    foreach my $fullname ( @_ ) {
        $_SDATA->{'METHOD'}{$fullname} = \&$fullname;
    }
    scrubber_enable_method(@_);
}

###----------------------------------------------------------------###
# Add/Remove entire packages

sub scrubber_remove_package {
    foreach my $package ( @_ ) {
        my @methods = grep { defined &{$_} } keys %Log::Scrubber::;
	foreach ( @methods ) {
            scrubber_remove_method($_);
	}
    }
}

sub scrubber_add_package {
    foreach my $package ( @_ ) {
        my @methods = grep { defined &{$_} } keys %Log::Scrubber::;
	foreach ( @methods ) {
            scrubber_add_method($_);
	}
    }
}

###----------------------------------------------------------------###
# Initilize the scrubber.  Wipe out any existing scrubbers/methods if they exist

sub scrubber_init {
    my $x = $_[0];
    if (defined $x) {
	scrubber_stop;
        $_SDATA = {
            'SIG' => {},
            'METHOD' => {},
            };
        scrubber_add_scrubber(@_);
    }
    scrubber_add_signal('WARN');
    scrubber_add_signal('DIE');
    scrubber_start();
    return 1;
}

=pod

The list of methods or functions that this module replaces are as
follows.

=item C<Carp::carp>

=item C<Carp::croak>

=item C<Carp::confess>

=item C<Carp::cluck>

All the methods from C<Carp> are overridden by this module.

=cut

scrubber_add_method('Carp::carp');
scrubber_add_method('Carp::croak');
scrubber_add_method('Carp::confess');
scrubber_add_method('Carp::cluck');

=pod

=item C<Sys::Syslog>

=item C<Unix::Syslog>

The known and common C<syslog()> calls are automatically overridden by
this module.

=cut

scrubber_add_method('main::syslog');

=pod

=item C<warnings::warn>

=item C<warnings::warnif>

Calls from C<warnings::> are automatically overridden by this module.

=cut

my $clone_warn = \&warnings::warn;
my $clone_warnif = \&warnings::warn;

*warnings::warn = sub
{
    @_ = scrubber @_;
    goto $clone_warn;
};

*warnings::warnif = sub
{
    @_ = scrubber @_;
    goto $clone_warnif;
};

1;
__END__

=pod

=back

=head2 METHODS

Additional methods created by this package.

  scrubber_init()		- Initialize the scrubber.
    scrubber_init()		- Use prevous scrubbing values.  Useful to maintain protection if you change $SIG
    scrubber_init( {		- Remove old scrubber regular expressions and set new ones.
      $ereg1 => $rep1,
      $ereg2 => $rep2,
      $ereg3 => $rep3,
      } )

  @clean = scrubber( @dirty )	- Allows manual use of the scrubber

=head2 EXPORT

Many. The methods are exported or overridden according to this

  $SIG{__WARN__}	-	Always overridden
  $SIG{__DIE__}		-	Always overridden
  warnings::warn()	-	Always overridden
  warnings::warnif()	-	Always overridden

  Carp::croak()		-	Only exported with :Carp or :all
  Carp::carp()		-	Only exported with :Carp or :all
  Carp::confess()	-	Only exported with :Carp or :all
  Carp::cluck()		-	Only exported with :Carp or :all

  main::syslog()	-	Only exported with :Syslog or :all

  scrubber_init()		-	Only exported with 'scrubber_init' or :Carp or :Syslog or :all
  scrubber()		-	Only exported with 'scrubber' or :all

=head1 HISTORY

=over 8

=item 0.01

Original version; created based off of source in Safe::Logs written by Luis E. Muñoz

=back


=head1 AUTHOR

Luis E. Muñoz <luismunoz@cpan.org>

=head1 SEE ALSO

perl(1), Carp(3), warnings(3), Sys::Syslog(3), Unix::Syslog(3)

=cut
