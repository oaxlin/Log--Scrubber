#!/usr/bin/perl

# Test the scrubber method

BEGIN 
{
    @crap = 
	(
	 "\x1bAll",
	 "yo\x1bur",
	 "bas\x1be",
	 "are\x1b",
	 "belong",
	 "to\x1b",
	 "\x1bus",
	 );
};

use Test::More tests => scalar @crap;
use Log::Scrubber qw(scrubber scrubber_init);

scrubber_init( { '\x1b' => '[esc]' } );

my @safe = scrubber @crap;

is($safe[0], '[esc]All');
is($safe[1], 'yo[esc]ur');
is($safe[2], 'bas[esc]e');
is($safe[3], 'are[esc]');
is($safe[4], 'belong');
is($safe[5], 'to[esc]');
is($safe[6], '[esc]us');


