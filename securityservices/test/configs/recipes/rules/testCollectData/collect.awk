BEGIN {
  FS = ":";
}
/ServiceContractReaderPlugin - Interception: ServiceContractRelay/ {
  x = substr($3,0,2);
  y =  substr($3,4,3);
  print $1 $2 x "."  y " " $5 " " $7 " " $8;
}

/MessageReaderAspect - Interception: message / {
  x = substr($3,0,2);
  y =  substr($3,4,3);
  print $1 $2 x "."  y " " $5 " " $7 " " $9;
}
