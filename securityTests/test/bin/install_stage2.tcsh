#!/bin/tcsh

set zipFilename = $1

set cipDirPrefix = ~/UL/cougaar

set cdir = `mktemp -d ${cipDirPrefix}.XXXX` 

# Stage 2: unzip files
cd ${CIP}
unzip -q ${zipFileName}

foreach f (cou*.zip)
  echo "Unzipping $f"
  unzip -q -o $f
end

foreach f (acme*.zip)
  echo "Unzipping $f"
  unzip -q -o $f
end

foreach f (*.tar)
  echo "Untar $f"
  tar xfz $f
end

foreach f (secur*.zip fwsupp*.zip)
  echo "Unzipping $f"
  unzip -q -o $f
end

