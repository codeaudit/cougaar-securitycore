#!/usr/bin/perl

$usage = "Usage: movediffs.pl [-c] <tag> <apply dir> [file1 [file2 [...]]]\
where -c forces a cvs commit with the appropriate log\
tag is the CVS tag to run the difference against\
apply dir is the directory containing the branch to modify files in\
\
You may provide file names on the command line or in stdin. If you use stdin\
then you must provide an EOF (^D) when you are finished if you are not using \
redirection.\n";
$#ARGV >= 1 || die $usage;
$tag = shift;
$commit = 0;
if ($tag eq "-c") {
  $commit = 1;
  $tag = shift;
}
$#ARGV >= 0 || die $usage;
$dir = shift;

if ($#ARGV == -1) {
  @files = ();
  while (<>) {
    chomp;
    push @files,$_;
  }
} else {
  @files = @ARGV;
  @ARGV = ();
}

for ($filenum = 0; $filenum <= $#files; $filenum++) {
  $file = $files[$filenum];
  $describe = 0;
  $lastDescription = "";

  %descriptions = ();
  @revisions    = ();
  $revision = "";
  $rcsfile = "";
  $mod_type = 0; # change
  $branch = "";

# first go through the log file for this file
  open LOG, "cvs log -r$tag" . ": $file|";
  while (<LOG>) {
    chomp;
#print "line: $_\n";
    if (/^[=]+$/) {
#     The description is done
      $lastDescription = ""; # kill the '----' line if it existed
      if ($description ne "") {
        $descriptions{$revision} = $description;
      }
    } elsif ($describe == 1) {
      if ($lastDescription ne "") {
        if (/revision /) {
          if ($revision ne "") {
            $descriptions{$revision} = $description;
          }
          s/revision //;
          $revision = $_;
          $lastDescription = "";
          $description = "";
          push @revisions, $revision;
          next;
        }
        $description = $description . $lastDescription . "\n";
        $lastDescription = "";
      }
      if ($description eq "" and /^date: /) {
#       date line, ignore it
        if (/state: dead;/) {
          $mod_type = 2; #deleted
        }
      } elsif (/^[-]+$/) {
        $lastDescription = $_;
      } else {
        $description = $description . $_ . "\n";
      }
    } if (/^description:$/) {
      $describe = 1;
    } elsif (/^RCS file: /) {
      s/^RCS file: //;
      s/,v$//;
      $rcsfile = $_;
    } elsif (/^head: /) {
      s/head: //;
      $head = $_;
    } elsif (/$tag:/) {
#      print "Found tag: $_\n";
      s/^.*($tag): //;
      $branch = $_;
#      print "tag: $branch\n";
    }
  }
  close LOG;

# make the file unicized
  print "file: $file: head rev $head -- $tag rev $branch\n";
  if ($branch eq "" and $mod_type == 0) {
#   it was an add since the branch doesn't have it
    print "Adding $file\n";
    $revision = $revisions[$#revisions];
    $tmpfile = "/tmp/tmpfile-$revision";
    chdir $dir;
    `cvs up -r $revision $file`;
    `cp $file $tmpfile`;
    unlink $file;
    `cvs up -r $tag $file`;
    `cp $tmpfile $file`;
    unlink $tmpfile;
    chdir "$ENV{PWD}";
    `dos2unix -q $dir/$file`;
    commit($file,$revision,0,1);
  } else {
    `dos2unix -q $dir/$file`;
  }

# now apply the differences for each revision to the branch
  for ($i = $#revisions; $i >= 0; $i--) {
    if ($i == $#revisions) {
      $fromrev = $revisions[i];
      $fromrev =~ s/([0-9]*\.[0-9]*)\..*/\1/;
    } else {
      $fromrev = $revisions[$i + 1];
    }
    $torev = $revisions[$i];
    print "cvs diff -c -r $fromrev -r $torev $file\n";
    open DIFF, "cvs diff -c -r $fromrev -r $torev $file|";
    $diff = "";
    $startdiff = 0;
    while (<DIFF>) {
      if ($startdiff == 0) {
        if (/^diff -c -r/) {
          $startdiff = 1;
        }
      } else {
        $diff .= $_;
      }
    }
    close DIFF;

#   patch the file using the 'patch' command.
    if ($i != 0 or $mod_type != 2) { # don't patch an 'rm', just delete it
#     update
      $patchfile = "patch-$revisions[$i]";
      open PATCH, ">$patchfile";
      print PATCH $diff;
      close PATCH;
      `dos2unix -q $patchfile`;
      `patch -c $dir/$file < $patchfile`;
      unlink $patchfile;
#      print $diff;
    }
    if ($i == 0 and $mod_type == 2) {
      $delete = 1;
    } else {
      $delete = 0;
    }
    commit($file,$revisions[$i],$delete,0);
#   commit the changes if the -c option was given
  } #end for each revision
} # end for each file

sub commit {
  local $file = shift;
  local $revision = shift;
  local $delete = shift;
  local $add = shift;

  chdir $dir;
  if ($add == 1 and $commit == 1) {
    print "cvs add $file\n";
    `cvs add $file`;
  }
  if ($delete == 1) {
    unlink $file;
    if ($commit == 1) {
#     must cvs rm before committing
      print "cvs rm $file\n";
      `cvs rm -f $file`;
    }
  }

  if ($commit == 1) {
    $tmpfile = "/tmp/desc-$revision";
    open DESC, ">$tmpfile";
    print DESC $descriptions{$revisions[$i]};
    close DESC;

    print "cvs commit -F $tmpfile $file\n";
    `cvs commit -F $tmpfile $file`;
    unlink $tmpfile;
  }
  chdir $ENV{PWD};
}
