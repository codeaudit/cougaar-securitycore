#!/bin/tcsh


#set keystoreFile=$CIP/configs/common/keystore-ROOT-RSA -storepass
#set keystorePassword='Ultra*Log'
set keystorePassword=keystorePassword

foreach i (`ls`)
  set keystoreFile=${i}/keystore-${i}
  keytool -import -file /mnt/shared/nai/sebastien/1ca.cer -keystore ${keystoreFile} -storepass "${keystorePassword}" -alias enclave1ca-1
  keytool -import -file /mnt/shared/nai/sebastien/2ca.cer -keystore ${keystoreFile} -storepass "${keystorePassword}" -alias enclave2ca-1
  keytool -import -file /mnt/shared/nai/sebastien/3ca.cer -keystore ${keystoreFile} -storepass "${keystorePassword}" -alias enclave3ca-1
  keytool -import -file /mnt/shared/nai/sebastien/4ca.cer -keystore ${keystoreFile} -storepass "${keystorePassword}" -alias enclave4ca-1
end
