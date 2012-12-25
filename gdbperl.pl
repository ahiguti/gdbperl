#!/usr/bin/env perl

# vim:sw=2:ts=8:ai

# gdbperl.pl - shows the call trace of a running perl process
# 
# Copyright (c) Akira Higuchi
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   Neither the name of the author nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# 
# Usage: gdbperl.pl PROCESS_ID [PERL_EXECUTABLE] [OPTION=VALUE [...]]
#        gdbperl.pl CORE_FILE PERL_EXECUTABLE [OPTION=VALUE [...]]

use strict;
use warnings;
use IPC::Open2;

my $core_or_pid = get_config(0);
my $array_limit = get_config("array_limit", 100);
my $hash_limit = get_config("hash_limit", 100);
my $data_limit = get_config("data_limit", 10);
my $show_stash = get_config("show_stash", undef);
my $exe = get_config(1, undef);
my $gdb_rh;
my $gdb_wh;
my $thread_prefix = '';
my $my_perl_prefix = '';
my $perl_version = 0;
my %value_map = ();

if (!$core_or_pid) {
  my $mess =
    "Usage: $0 PROCESS_ID [PERL_EXECUTABLE] [OPTION=VALUE [...]]\n" .
    "Usage: $0 CORE_FILE PERL_EXECUTABLE [OPTION=VALUE [...]]\n";
  die "$mess";
}
my $is_pid = ($core_or_pid =~ /^\d+$/);
if ($is_pid && !defined($exe)) {
  $exe = readlink("/proc/$core_or_pid/exe") # linux
}
if ($is_pid && !defined($exe)) {
  $exe = `which perl`;
  chomp($exe);
}
die "failed to detect perl executable" if !$exe;

trace_one($core_or_pid, $exe);
exit 0;

sub trace_one {
  my ($core_or_pid, $exe) = @_;
  my $cmd = "gdb -silent -nw $exe $core_or_pid";
  print "command:\n$cmd\n\n";
  my $pid = open2($gdb_rh, $gdb_wh, "$cmd 2>&1") or die "$cmd";
  eval {
    show_trace();
  };
  my $err = $@;
  if ($is_pid) {
    system("kill -CONT $core_or_pid 2>/dev/null");
  }
  close($gdb_rh);
  close($gdb_wh);
  die $err if $err;
}

sub log_gdb {
  my ($pre, $mess) = @_;
  return if (!get_config('verbose_gdb', 0));
  my @lines = split(/\n/, $mess);
  for my $line (@lines) {
    print "$pre: $line\n";
  }
}

sub cmd_exec {
  my $cmd = $_[0];
  log_gdb('C', $cmd);
  if ($cmd) {
    my $r = syswrite($gdb_wh, $cmd);
    if ($r < length($cmd)) {
      die "failed to send: [$cmd]\n";
    }
  }
  my $resp = '';
  while (1) {
    my $buf = '';
    my $r = sysread($gdb_rh, $buf, 1024);
    if ($r <= 0) {
      last;
    }
    $resp .= $buf;
    if ($resp =~ /\(gdb\) $/) {
      last;
    }
  }
  log_gdb('R', $resp);
  return $resp;
}

sub cmd_get_value {
  my $cmd = $_[0];
  my $resp = cmd_exec($cmd);
  return '' if ($resp !~ / =\s+(.+)/);
  my $v = $1;
  if ($resp =~ /0x\w+\s+\"(.*)\"/) {
    return $1;
  }
  return $v;
}

sub shorten_expr {
  my $expr = $_[0];
  return $expr if ($expr =~ /\$\d+$/);
  my $resp = cmd_exec("p $expr\n");
  if ($resp =~ /(\$\d+)/) {
    return "$1";
  }
  return $expr;
}

sub show_environ {
  my $resp = '';
  my $i = 0;
  print "environ:\n";
  while (1) {
    my $resp = cmd_get_value("p ((char **)environ)[$i]\n");
    last if ($resp eq '' || $resp eq '0x0');
    print "$resp\n";
    ++$i;
  }
  print "\n";
}

sub get_hvname {
  my $hvstr = shorten_expr($_[0]);
  if ($perl_version <= 8) {
    return cmd_get_value("p $hvstr->sv_any->xhv_name\n");
  }
  my $hvmax = cmd_get_value("p $hvstr->sv_any->xhv_max\n");
  if ($hvmax =~ /\d+/) {
    my $hvauxstr =
      "(struct xpvhv_aux *)($hvstr->sv_u.svu_hash+$hvmax+1)";
    if ($perl_version >= 14) {
      my $hvnamestr = "(char *)($hvauxstr)->xhv_name_u.xhvnameu_name";
      return cmd_get_value("p $hvnamestr->hek_key\n");
    } else {
      return cmd_get_value("p (char *)($hvauxstr)->xhv_name->hek_key\n");
    }
  }
  return '';
}

sub get_perl_cop {
  my $base = shorten_expr($_[0]);
  my $cop_file;
  if ($thread_prefix eq '') {
    if ($perl_version >= 10) {
      $cop_file = "$base->cop_filegv->sv_u.svu_gp->gp_sv->sv_u.svu_pv";
    } else {
      $cop_file = "((XPV *)($base->cop_filegv->sv_any->xgv_gp->gp_sv->sv_any))"
	. "->xpv_pv";
    }
  } else {
    $cop_file = "$base->cop_file";
  }
  my $file = cmd_get_value("p $cop_file\n");
  my $line = cmd_get_value("p $base->cop_line\n");
  if (get_config('perl_package', 1)) {
    my $ns;
    if ($thread_prefix eq '') {
      $ns = get_hvname("$base->cop_stash");
    } else {
      $ns = cmd_get_value("p $base->cop_stashpv\n");
    }
    return "$file:$line($ns)";
  }
  return "$file:$line";
}

sub sv_is_undef {
  my $estr = $_[0];
  my $svt = cmd_get_value("p $estr->sv_flags\n");
  if (!defined($svt) || $svt !~ /^\d+$/) {
    return 1;
  }
  my $typ = $svt & 0xff;
  return ($typ == 0);
}

sub get_ptr {
  my $str = $_[0];
  if ($str =~ /\(\w+ \*\)\s+(.+)/) {
    return $1;
  }
  return $str;
}

sub get_perlsv {
  my ($estr, $digkey, $depth) = @_;
  if (is_empty_key($digkey)) {
    return '-' if (++$depth >= $data_limit);
  }
  $estr = shorten_expr($estr);
  my $value_ptr = get_ptr(cmd_get_value("p $estr\n"));
  if (defined $value_map{$value_ptr}) {
    return $value_ptr;
  }
  # print STDERR "$estr PTR = $value_ptr\n";
  my $svt = cmd_get_value("p $estr->sv_flags\n");
  if (!defined($svt) || $svt !~ /^\d+$/) {
    return '??';
  }
  my $typ = $svt & 0xff;
  return 'undef' if $typ == 0;
  my $rv = '';
  my $reuse_flag = 0;
  if ($perl_version >= 12) {
    return 'ref' if ($svt & 0x0800) != 0 && $typ == 2;
    return cmd_get_value("p ((XPVIV*)$estr->sv_any)->xiv_u.xivu_iv\n")
      if $typ == 2;
    return cmd_get_value("p ((XPVNV*)$estr->sv_any)->xnv_u.xnv_nv\n")
      if $typ == 3;
    return '"' . cmd_get_value("p $estr->sv_u.svu_pv\n") . '"' if $typ >= 4;
    $rv = '?';
  } elsif ($perl_version >= 10) {
    return cmd_get_value("p ((XPVIV*)$estr->sv_any)->xiv_u.xivu_iv\n")
      if $typ == 2;
    return cmd_get_value("p ((XPVNV*)$estr->sv_any)->xnv_u.xnv_nv\n")
      if $typ == 3;
    return 'ref' if $typ == 4;
    return '"' . cmd_get_value("p $estr->sv_u.svu_pv\n") . '"' if $typ >= 5;
    $rv = '?';
  } else {
    my $objstr = '';
    if (($svt & 0x1000) != 0) {
      $objstr = get_hvname("((XPVMG*)$estr->sv_any)->xmg_stash")
    }
    if ($typ >= 13) {
      $rv .= get_perlgv($estr, $digkey, $depth);
      $reuse_flag = 1;
    } elsif ($typ >= 12) {
      $rv .= "(CV)";
    } elsif ($typ >= 11) {
      $rv .= get_perlhv($estr, $digkey, $depth);
      $reuse_flag = 1;
    } elsif ($typ >= 10) {
      $rv .= get_perlav($estr, $digkey, $depth);
      $reuse_flag = 1;
    } elsif ($typ >= 4) {
      $rv .= '"' . cmd_get_value("p ((XPV*)$estr->sv_any)->xpv_pv\n") . '"';
    } elsif ($typ >= 3) {
      $rv .= get_perlrv($estr, $digkey, $depth);
    } elsif ($typ >= 2) {
      $rv .= cmd_get_value("p ((XPVNV*)$estr->sv_any)->xnv_nv\n");
    } elsif ($typ >= 1) {
      $rv .= cmd_get_value("p ((XPVIV*)$estr->sv_any)->xiv_iv\n");
    } else {
      return 'undef';
    }
    if ($objstr) {
      $rv = "(BLESS: '$objstr' $rv)";
    }
  }
  if ($reuse_flag) {
#    $value_map{$value_ptr} = $rv;
#    $rv = "$value_ptr $rv";
  }
  return $rv;
}

sub is_empty_key {
  my $digkey = $_[0];
  return !$digkey || scalar(@$digkey) == 0;
}

sub get_perlrv {
  my ($estr, $digkey, $depth) = @_;
  # return '-' if $depth >= $data_limit;
  my $s = '';
  if ($perl_version >= 10) {
    $s = get_perlsv("((XRV*)$estr->sv_any)->xrv_u.xrv_rv", $digkey, $depth);
      # TODO: test
  } else {
    $s = get_perlsv("((XRV*)$estr->sv_any)->xrv_rv", $digkey, $depth);
  }
  # if ($s =~ /^\{/ || $s =~ /^\[/) { return $s; }
  return is_empty_key($digkey) ? "\\$s" : $s;
}

sub get_perlhv {
  my ($estr, $digkey, $depth) = @_;
  # return '-' if $depth >= $data_limit;
  # TODO: perl >= 5.10
  my $hvarr = shorten_expr("(*(HE***)&((XPVHV*)($estr->sv_any))->xhv_array)");
  my $hvmax = cmd_get_value("p ((XPVHV*)($estr->sv_any))->xhv_max\n");
  my $rstr = '(';
  my $count = 0;
  my $hvarr_val = cmd_get_value("p $hvarr\n");
  if ($hvarr_val =~ /\s0x0$/) {
    return "(HV)";
  }
  my $truncated = 0;
  for (my $i = 0; $i <= $hvmax; ++$i) {
    last if $truncated;
    my $eelem = $hvarr . '[' . $i . ']'; # 1st entry of the bucket
    while (1) {
      my $he = cmd_get_value("p $eelem\n");
      last if $he =~ /\s0x0$/;
      my $kstr = cmd_get_value("p (char *)$eelem->hent_hek->hek_key\n");
      if ($digkey && scalar(@$digkey)) {
	my $k = $digkey->[0];
	if ($k eq $kstr) {
	  shift(@$digkey);
	  return get_perlsv("$eelem->hent_val", $digkey, $depth);
	}
      } else {
	my $vstr = get_perlsv("$eelem->hent_val", $digkey, $depth);
	if ($count >= $hash_limit) {
	  $rstr .= ", ...";
	  $truncated = 1;
	  last;
	}
	$rstr .= ', ' if ($count != 0);
	$rstr .= $kstr . ' => ' . $vstr;
	++$count;
      }
      $eelem = shorten_expr("$eelem->hent_next"); # next entry in the bucket
    }
  }
  if ($digkey && scalar(@$digkey)) {
    my $k = $digkey->[0];
    return "(HV: '$k' NOTFOUND)";
  }
  $rstr .= ')';
  return $rstr;
}

sub get_perlav {
  my $arr = get_perlav_as_array(@_);
  my $rstr = '(';
  if ($arr) {
    for (my $i = 0; $i < scalar(@$arr); ++$i) {
      $rstr .= ', ' if ($i != 0);
      $rstr .= $arr->[$i];
    }
  }
  $rstr .= ')';
  return $rstr;
}

sub macro_avarray {
  my $s = $_[0];
  if ($perl_version >= 10) {
    return "($s->sv_u.svu_array)";
  } else {
    return "((SV**)($s->sv_any)->xav_array)";
  }
}

sub get_perlav_as_array {
  my ($avstr, $digkey, $depth) = @_; # (SV*) or (AV*)
  # return '-' if $depth >= $data_limit;
  $avstr = shorten_expr("((AV*)($avstr))");
  my $avfill = cmd_get_value("p $avstr->sv_any->xav_fill\n");
  return '' if (!defined($avfill) || $avfill < 0);
  my @arr = ();
  for (my $i = 0; $i <= $avfill; ++$i) {
    last if ($i >= $array_limit);
    my $estr = macro_avarray($avstr) . "[$i]";
    my $e = get_perlsv($estr, $digkey, $depth);
    push(@arr, $e);
  }
  return \@arr;
}

sub get_perlgv {
  my ($gvstr, $digkey, $depth) = @_;
  # return '-' if $depth >= $data_limit;
  my @rarr = ();
  my $gpstr = shorten_expr("((XPVGV*)($gvstr)->sv_any)->xgv_gp");
  my $gvcv = cmd_get_value("p $gpstr->gp_cv\n");
  if ($gvcv && $gvcv !~ / 0x0$/) {
    push(@rarr, '(CV)');
  }
  my $gvhv = cmd_get_value("p $gpstr->gp_hv\n");
  if ($gvhv && $gvhv !~ / 0x0$/) {
    push(@rarr, get_perlhv("$gpstr->gp_hv", $digkey, $depth));
  }
  my $gvav = cmd_get_value("p $gpstr->gp_av\n");
  if ($gvav && $gvav !~ / 0x0$/) {
    push(@rarr, get_perlav("$gpstr->gp_av", $digkey, $depth));
  }
  my $gvsv = cmd_get_value("p $gpstr->gp_sv\n");
  if ($gvsv && $gvsv !~ / 0x0$/) {
    if (!sv_is_undef("$gpstr->gp_sv")) {
      push(@rarr, get_perlsv("$gpstr->gp_sv", $digkey, $depth));
    }
  }
  if (is_empty_key($digkey) || scalar(@rarr) == 1) {
    return $rarr[0] || '(GV)';
  }
  return "(GV: " . join(', ', grep { defined ($_) } @rarr) . ")";
}

sub get_sub_args {
  my ($block_sub) = @_;
  return '' if ($data_limit <= 0);
  my $avstr = shorten_expr("$block_sub.argarray");
  return get_perlav($avstr, undef, 0);
}

sub get_sub_locals {
  my ($block_sub) = @_;
  my $cur_cv = shorten_expr("$block_sub.cv");
  my $idx = cmd_get_value("p $block_sub.olddepth\n") + 1;
  my $padlist = shorten_expr("((XPVCV*)($cur_cv)->sv_any)->xcv_padlist");
  my $plarr = macro_avarray($padlist);
  my $padlistarray = shorten_expr("((PAD **)($plarr))");
  my $namesarr = $padlistarray . "[0]";
  my $valsarr = $padlistarray . "[$idx]";
  my $names = get_perlav_as_array($namesarr);
  my $vals = get_perlav_as_array($valsarr);
  my $len = scalar(@$names);
  my $rstr = '';
  for (my $i = 0; $i < $len; ++$i) {
    my $n = $names->[$i];
    next if ($n eq 'undef');
    my $v = $vals->[$i];
    $rstr .= ', ' if $rstr ne '';
    $rstr .= "$n := $v";
  }
  return $rstr;
}

sub get_cxtype_str {
  my ($typ) = @_;
  return 'unknown' if (!defined($typ) || $typ !~ /\d+/);
  if ($perl_version >= 12) {
    return 'sub' if $typ == 8;
    return 'eval' if $typ == 10;
    return 'loop' if ($typ & 0xc) == 0x4;
  } else {
    return 'sub' if $typ == 1;
    return 'eval' if $typ == 2;
    return 'loop' if $typ == 3;
  }
  return 'other';
}

sub get_perl_frame {
  my ($stackexpr, $i) = @_;
  my $copstr = $stackexpr . '[' . $i . ']';
  my $pos = get_perl_cop("$copstr.cx_u.cx_blk.blku_oldcop");
  my $sargs = '';
  my $locals = '';
  if (get_config('perl_func', 1)) {
    my ($typ, $ns, $func, $callee) = (-1, '', '', '(unknown)');
    if ($perl_version >= 12) {
      $typ = cmd_get_value("p $copstr.cx_u.cx_subst.sbu_type & 0xf\n");
    } elsif ($perl_version >= 10) {
      $typ = cmd_get_value("p $copstr.cx_u.cx_subst.sbu_type & 0xff\n");
    } else {
      $typ = cmd_get_value("p $copstr.cx_type & 0xff\n");
    }
    my $typstr = get_cxtype_str($typ);
    if ($typstr eq 'sub') {
      my $block_sub = shorten_expr("$copstr.cx_u.cx_blk.blk_u.blku_sub");
      my $gvstr = "$block_sub.cv->sv_any->xcv_gv->sv_any";
      if ($perl_version >= 10) {
	my $hvstr = "$gvstr.xnv_u.xgv_stash";
	$ns = get_hvname($hvstr);
	$func = cmd_get_value(
	  "p (char *)$gvstr.xiv_u.xivu_namehek->hek_key\n");
      } else {
	$ns = cmd_get_value("p $gvstr->xgv_stash->sv_any->xhv_name\n");
	$func = cmd_get_value("p $gvstr->xgv_name\n");
      }
      $ns = '' if $ns eq '0x0';
      $func = '' if $func eq '0x0';
      $sargs = "ARGS: " . get_sub_args($block_sub);
      $locals = "LOCALS: " . get_sub_locals($block_sub);
      $callee = ($ns || $func) ? ($ns . '::' . $func) : '(unknown)';
    } else {
      $callee = "($typstr)";
    }
    return "[$i] $pos -> $callee $sargs $locals";
  } else {
    return "[$i] $pos";
  }
}

sub check_perl_version {
  $perl_version = cmd_get_value("p PL_version\n");
  $perl_version =~ s/ .+//g;
  $perl_version = 8 if !$perl_version;
  my $p;
  $p = cmd_get_value("p PL_curcop->cop_line\n");
  if ($p) {
    $thread_prefix = '';
    $my_perl_prefix = 'PL_';
    return;
  }
  $p = cmd_get_value("p my_perl->Tcurcop->cop_line\n");
  if ($p) {
    $thread_prefix = 'T'; # perl 5.8 with ithreads
    $my_perl_prefix = 'my_perl->T';
    return;
  }
  $p = cmd_get_value("p my_perl->Icurcop->cop_line\n");
  if ($p) {
    $thread_prefix = 'I'; # perl >= 5.10 with ithreads
    $my_perl_prefix = 'my_perl->I';
    return;
  }
  die "unknown perl version";
}

sub show_trace {
  my ($resp, $fr, $depth) = ('', -1, -1);
  $resp = cmd_exec('');
  $resp = cmd_exec("set pagination off\n");
  show_environ() if get_config('env', 1);
  $resp = cmd_exec("bt\n");
  my $show_c_trace = get_config('c_trace', 1);
  print "c_backtrace:\n" if $show_c_trace;
  for my $line (split(/\n/, $resp)) {
    if ($line =~ /\#(\d+) .+my_perl\=0x/) {
      $fr = $1;
    }
    last if ($line eq '(gdb) ');
    print "$line\n" if $show_c_trace;
  }
  print "\n" if $show_c_trace;
  $resp = cmd_exec("fr $fr\n");
  check_perl_version();
  print "perl5_version:\n$perl_version$thread_prefix\n\n";
  my $cur_op = get_perl_cop("${my_perl_prefix}curcop");
  print "perl_cur_op:\n$cur_op\n\n";
  $depth = cmd_get_value("p ${my_perl_prefix}curstackinfo->si_cxix\n");
  if ($depth !~ /\d+/) {
    $depth = 0;
  } elsif ($depth > 1000) {
    $depth = 1000;
  }
  print "perl_backtrace:\n";
  my $stackexpr = shorten_expr("${my_perl_prefix}curstackinfo->si_cxstack");
  for (my $i = $depth; $i > 0; --$i) {
    my $pfr = get_perl_frame($stackexpr, $i);
    print "$pfr\n";
  }
  print "\n";
  if ($show_stash) {
    my @keyarr = split(/\//, $show_stash);
    my $defstash = get_perlhv("${my_perl_prefix}defstash", \@keyarr, 0);
    print "stash '$show_stash':\n";
    print "$defstash\n";
  }
  cmd_get_value("detach\n");
  cmd_get_value("quit\n");
}

sub get_config {
  our $confmap;
  our $confarr;
  if (!defined($confmap)) {
    $confmap = +{};
    $confarr = +[];
    my $arridx = 0;
    for my $kv (@ARGV) {
      if ($kv =~ /^(\w+)=(.+)$/) {
        $confmap->{$1} = $2;
      } else {
        $confarr->[$arridx++] = $kv;
      }
    }
  }
  my $digkey = $_[0];
  my $v = ($digkey =~ /^\d+$/) ? $confarr->[$digkey] : $confmap->{$digkey};
  return defined($v) ? $v : $_[1];
}

