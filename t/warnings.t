#!/usr/bin/perl

# Test the warning:: overrides

use Test::More tests => 6;
use warnings;
use warnings::register;
use Log::Scrubber;

scrub_init( {
    '\x1b' => '[esc]',
    '4007000000027' => 'X' x 13,
    '1234' => 'X' x 4,
} );

END { unlink "test.out"; }

sub _read
{
    open FILE, "test.out";
    my $ret = join('', <FILE>);
    close FILE;
    return $ret;
}

sub _setup
{
    open STDERR, ">test.out";
    select((select(STDERR), $|++)[0]);
}

my $tests = {
    "escape --> \x1b\n" => "escape --> [esc]\n",
    "escape --> 4007000000027\n" => "escape --> XXXXXXXXXXXXX\n",
    "escape --> 1234\n" => "escape --> XXXX\n",
};

foreach my $key ( keys %$tests ) {
    eval { 
        _setup;
        warnings::warn($key);
    };

    ok(index(_read, $tests->{$key}) != -1, "warnings::warn");

    eval { 
        _setup;
        warnings::warnif("void", $key);
    };

    ok(index(_read, $tests->{$key}) != -1, "warnings::warnif");
}
