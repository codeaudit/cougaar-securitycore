BEGIN {
  FS = ":";
  print "use test"
    }

/BlackBoardCollectorPlugin - Interception: ReportForDuty with role / {
  if ($7 == " Subordinate") {
    n = split($5, a, "[ ]*") ;
    subordinate = a[n-1]  ;
    subordinate = substr(subordinate, 0, length(subordinate)-1);

    n = split($6, a, "[ ]*") ;
    superior = a[n-1]  ;
    superior = substr(superior, 0, length(superior)-1);

    if (superior != "") {
      print "delete from unused_subordinates";
      print "   where subordinate = '" subordinate "' and superior = '" superior "';";
    }
  } 
}
