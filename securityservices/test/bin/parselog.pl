#!/usr/bin/perl

$tag = shift;
$file = "";
$describe = 0;
$description = "";

open LOG, "cvs log -r$tag" . "::|";
while (<LOG>) {
  chomp;
  if (/^[=]+$/) {
    if ($file ne "" and $head ne "" and $branch ne "" and $describe == 1 and
        $head ne $branch) {
      print "$file: HEAD $head, $tag $branch\n";
      print "$description";
      print "=============================================================================\n";
    }
    $file = "";
    $head = "";
    $branch = "";
    $describe = 0;
    $description = "";
  } elsif ($describe == 1) {
    $description = $description . $_ . "\n";
#    print "description: $description";
  } if (/^description:$/) {
    $describe = 1;
  } elsif (/^RCS file: /) {
    s/^RCS file: //;
    s/,v$//;
    $file = $_;
  } elsif (/^head: /) {
    s/head: //;
    $head = $_;
  } elsif (/$tag:/) {
#    print "Found tag: $_\n";
    s/^.*($tag): //;
    $branch = $_;
#    print "tag: $branch\n";
  }
}

close LOG;
