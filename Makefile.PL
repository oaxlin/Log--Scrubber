use ExtUtils::MakeMaker;

# $Id: Makefile.PL,v 1.1.1.1 2003/03/03 05:20:28 lem Exp $

WriteMakefile(
    'NAME'		=> 'Log::Scrubber',
    'VERSION_FROM'	=> 'Scrubber.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
	      ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
	       (ABSTRACT_FROM	=> 'Scrubber.pm',
		AUTHOR     	=> 'Jason Terry') : ()),

);
