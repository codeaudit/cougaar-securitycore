#!/bin/tcsh

set zipFileName = cougaar-test.zip

set cipDirPrefix = ~/UL/cougaar

set cdir = `mktemp -d ${cipDirPrefix}.XXXX` 

# Stage 2: unzip files
cd ${CIP}
echo "Unzipping ${zipFileName}"
unzip -q -o ${zipFileName}

foreach f (cougaar.zip cougaar-support.zip)
  echo "Unzipping $f"
  unzip -q -o $f
end

foreach f (acme*.zip)
  echo "Unzipping $f"
  unzip -q -o $f
end

foreach f (*.tar.gz)
  echo "Untar $f"
  tar xfz $f
end

foreach f (secur*.zip fwsupp*.zip)
  echo "Unzipping $f"
  unzip -q -o $f
end

