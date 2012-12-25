#!perl
use strict;
use warnings;
use Test::More;

use BSD::Resource;

setrlimit(RLIMIT_CORE, RLIM_INFINITY, RLIM_INFINITY);

system("$^X t/scripts/hello.pl");

my $core_file = $^O eq 'darwin' ? "/cores/core.$?" : "./core.$?";

my $d = `./gdbperl.pl $core_file $^X`;

isnt $d, "", "something shown for $core_file";

unlink($core_file);

done_testing;
