package Log::Scrubber;

require 5.005;
use strict;
use warnings;
use Carp;
no warnings "redefine";		# We make this a few times

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION = '0.01';

require Exporter;

@ISA = qw(Exporter);

@EXPORT = qw(scrub_init);

%EXPORT_TAGS =
(
 Carp		=> [ qw(scrub_init carp croak confess cluck) ],
 Syslog		=> [ qw(scrub_init syslog) ],
 );

push @{$EXPORT_TAGS{all}}, @{$EXPORT_TAGS{$_}} 
for grep { $_ ne 'all' } keys %EXPORT_TAGS;

push @{$EXPORT_TAGS{all}}, 'scrub';
push @{$EXPORT_TAGS{all}}, 'scrub_init';

@EXPORT_OK = @{$EXPORT_TAGS{all}}; 

=pod

=head1 NAME

Log::Scrubber - Perl extension to avoid logging sensitive data

=head1 SYNOPSIS

  use Log::Scrubber;		# Always override warn() and die() and import scrub_init()
  use Log::Scrubber qw(:all);	# override eveything this module knows
  use Log::Scrubber qw(:Carp);	# Only override Carp:: methods
  use Log::Scrubber qw(:Syslog);	# Only override syslog()
  use Log::Scrubber qw(scrub);	# scrub() for use on your own

				# Or combine a few
  use Log::Scrubber qw(:Syslog :Carp);

  Example:

    scrub_init( { '4007000000027' => 'DELETED' } );
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

The protection can also be invoked by the C<scrub> method, which
takes a list of arguments and returns the same list, with all ESC
characters safely replaced. This method is provided so that you can
call it by yourself.

Typically, you will want to issue an C<use Log::Scrubber qw(:all)> after
the last module is C<use>d in your code, to automatically benefit from
the most common level of protection.

Note: If your using your own $SIG{__WARN__} and $SIG{__DIE__} then you
must call scrub_ini() afterward to maintain full protection.

=cut

				# This is the core of our protection. Replace
				# the data by the value provided

my $_scrub_protected = ();
my ($new_warn, $new_die, $old_warn, $old_die);
sub _scrub {
    my $msg = $_[0];
    return $_[0] if ref $_[0];
    #$msg =~ s/\x1b/[esc]/g;
    foreach ( keys %$_scrub_protected ) {
        $msg =~ s/$_/$_scrub_protected->{$_}/g;
    }
    return $msg;
}

sub scrub_init {
    my $x = $_[0];
    if (defined $x) {
        $_scrub_protected = ();
        foreach ( keys %$x ) { $_scrub_protected->{$_} = $x->{$_}; }
    }
    if ( $new_warn ne $SIG{__WARN__} ) { _init_warn(); }
    if ( $new_die ne $SIG{__DIE__} ) { _init_die(); }
    return %$_scrub_protected;
}

sub scrub {
    return map { _scrub $_ } @_;
}

=pod

The list of methods or functions that this module replaces are as
follows.

=cut

				# This eases the task of replacing a method
				# from other package

sub _build
{
    no strict 'refs';
    my $name = shift;
    my $r_orig = \&$name;
    $name =~ s/^.*:://;
    *$name = sub { $r_orig->( scrub @_ ) };
}

=pod

=over

=item C<warn>

The standard Perl C<warn()>.

=cut

$new_warn = sub {
    @_ = scrub @_;
    defined $old_warn ? $old_warn->(@_) : CORE::warn(@_);
};
sub _init_warn {
    $old_warn = $SIG{__WARN__} unless defined $old_warn && $old_warn eq $new_warn;
    $SIG{__WARN__} = $new_warn;
}
_init_warn;

=pod

=item C<die>

The standard Perl C<die()>.

=cut

$new_die = sub {
    @_ = scrub @_;
    defined $old_die ? $old_die->(@_) : CORE::die(@_);
};
sub _init_die {
    $old_die = $SIG{__DIE__} unless defined $old_die && $old_die eq $new_die;
    $SIG{__DIE__} = $new_die;
}
_init_die;

=pod

=item C<Carp::carp>

=item C<Carp::croak>

=item C<Carp::confess>

=item C<Carp::cluck>

All the methods from C<Carp> are overridden by this module.

=cut

_build('Carp::carp');
_build('Carp::croak');
_build('Carp::confess');
_build('Carp::cluck');

=pod

=item C<Sys::Syslog>

=item C<Unix::Syslog>

The known and common C<syslog()> calls are automatically overridden by
this module.

=cut

_build('main::syslog');

=pod

=item C<warnings::warn>

=item C<warnings::warnif>

Calls from C<warnings::> are automatically overridden by this module.

=cut

my $clone_warn = \&warnings::warn;
my $clone_warnif = \&warnings::warn;

*warnings::warn = sub
{
    @_ = scrub @_;
    goto $clone_warn;
};

*warnings::warnif = sub
{
    @_ = scrub @_;
    goto $clone_warnif;
};

1;
__END__

=pod

=back

=head2 METHODS

Additional methods created by this package.

  scrub_init()		- Initialize the scrubber.
    scrub_init()		- Use prevous scrubbing values.  Useful to maintain protection if you change $SIG
    $ret = scrub_init()		- Get a hash of current scrub values (USE WITH CAUTION)
    scrub_init( {		- Remove old scrub regular expressions and set new ones.
      $ereg1 => $rep1,
      $ereg2 => $rep2,
      $ereg3 => $rep3,
      } )

  @clean = scrub( @dirty )	- Allows manual use of the scrubber

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

  scrub_init()		-	Only exported with 'scrub_init' or :Carp or :Syslog or :all
  scrub()		-	Only exported with 'scrub' or :all

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
