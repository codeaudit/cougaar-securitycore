#!/bin/tcsh

foreach dir ( coordinator fwsupport securemonitoring securityTests dataprotection \
              moptools securebootstrapper securityservices  securityutils )
  echo $dir
  #ls ../$dir/build/lib
  #cp build/lib/*.jar ../$dir/build/lib
  cd ../$dir
  #cvs add -m build/lib/*.jar
  cvs commit -m ../installer/commit.txt build/lib
end

