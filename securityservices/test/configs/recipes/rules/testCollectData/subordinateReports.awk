BEGIN {
  FS = ":";
  print "use cougaar104"
  print "create table if not exists csi_subordinate_reported"
  print "    (subordinate varchar(150), superior varchar(150));"
  print "delete from csi_subordinate_reported;"
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
      print "insert into csi_subordinate_reported";
      print "   values ('" subordinate "', '" superior "');";
    }
  } 
}
