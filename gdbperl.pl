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
#   Neither the name of the <ORGANIZATION> nor the names of its contributors
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

use strict;
use warnings;
use IPC::Open2;

my $core_or_pid = get_config(0)
  or die "Usage: $0 PROCESS_ID [PERL_EXECUTABLE]";
my $exe = get_config(1, undef);
my $is_pid = ($core_or_pid =~ /^\d+$/);
my $gdb_rh;
my $gdb_wh;
my $thread_prefix = '';
my $my_perl_prefix = '';
my $perl_version = 0;

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
    system("kill -CONT $core_or_pid");
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
  if ($resp =~ /0x\w+\s+\"(.+)\"/) {
    return $1;
  }
  return $v;
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
  my $hvstr = $_[0];
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
  my $base = $_[0];
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

sub get_perl_value {
  my ($estr) = @_;
  my $svt = cmd_get_value("p $estr.sv_flags\n");
  if (!defined($svt) || $svt !~ /^\d+$/) {
    return '?';
  }
  my $typ = $svt & 0xff;
  return 'undef' if $typ == 0;
  if ($perl_version >= 12) {
    return 'ref' if ($svt & 0x0800) != 0 && $typ == 2;
    return cmd_get_value("p ((XPVIV*)$estr.sv_any)->xiv_u.xivu_iv\n")
      if $typ == 2;
    return cmd_get_value("p ((XPVNV*)$estr.sv_any)->xnv_u.xnv_nv\n")
      if $typ == 3;
    return '"' . cmd_get_value("p $estr.sv_u.svu_pv\n") . '"' if $typ >= 4;
  } elsif ($perl_version >= 10) {
    return cmd_get_value("p ((XPVIV*)$estr.sv_any)->xiv_u.xivu_iv\n")
      if $typ == 2;
    return cmd_get_value("p ((XPVNV*)$estr.sv_any)->xnv_u.xnv_nv\n")
      if $typ == 3;
    return 'ref' if $typ == 4;
    return '"' . cmd_get_value("p $estr.sv_u.svu_pv\n") . '"' if $typ >= 5;
  } else {
    return cmd_get_value("p ((XPVIV*)$estr.sv_any)->xiv_iv\n") if $typ == 1;
    return cmd_get_value("p ((XPVNV*)$estr.sv_any)->xnv_nv\n") if $typ == 2;
    return 'ref' if $typ == 3;
    return '"' . cmd_get_value("p ((XPV*)$estr.sv_any)->xpv_pv\n") . '"'
      if $typ >= 4;
  }
  return '?';
}

sub get_sub_args {
  my ($copstr) = @_;
  my $avstr = "$copstr.cx_u.cx_blk.blk_u.blku_sub.argarray";
  my $avfill = cmd_get_value("p $avstr->sv_any->xav_fill\n");
  return '' if (!defined($avfill) || $avfill < 0);
  $avfill = 100 if $avfill > 100;
  my $rstr = '';
  for (my $i = 0; $i <= $avfill; ++$i) {
    $rstr .= ', ' if ($i != 0);
    my $estr = '';
    if ($perl_version >= 10) {
      $estr = "($avstr->sv_u.svu_array[$i])";
    } else {
      $estr = "(*((SV**)($avstr->sv_any)->xav_array)[$i])";
    }
    $rstr .= get_perl_value($estr);
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
  my ($i) = @_;
  my $copstr = "${my_perl_prefix}curstackinfo->si_cxstack[$i]";
  my $pos = get_perl_cop("$copstr.cx_u.cx_blk.blku_oldcop");
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
      my $gvstr = "$copstr.cx_u.cx_blk.blk_u.blku_sub.cv->sv_any"
          . "->xcv_gv->sv_any";
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
      my $sargs = get_config('perl_args', 1) ? get_sub_args($copstr) : '';
      $callee = ($ns || $func) ? ($ns . '::' . $func . '(' . $sargs . ')')
             : '(unknown)';
    } else {
      $callee = "($typstr)";
    }
    return "[$i] $callee <- $pos";
  } else {
    return "[$i] <- $pos";
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
    if ($line =~ /\#(\d+) .+my_perl/) {
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
  for (my $i = $depth; $i > 0; --$i) {
    my $pfr = get_perl_frame($i);
    print "$pfr\n";
  }
  print "\n";
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
  my $key = $_[0];
  my $v = ($key =~ /^\d+$/) ? $confarr->[$key] : $confmap->{$key};
  return defined($v) ? $v : $_[1];
}

