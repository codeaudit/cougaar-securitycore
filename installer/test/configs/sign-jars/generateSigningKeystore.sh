#!/bin/sh

keystorefile=signingCA_keystore
keystorepwd=keystore
daysvalid=24855

bootstrap_keystore=../../../../securebootstrapper/test/configs/security/bootstrap_keystore

# Note: 24855 days= 24,855 * 24 * 60 * 60 seconds, which is < 2^31,
# but adding one more day and the number of seconds is higher than 2^31,
# and keytool will not work.

genkey() {
  alias=$1
  dname=$2
  echo "Generate key: alias=$alias"
  keytool -genkey -alias $alias -keyalg RSA -keysize 1024 -sigalg SHA1withRSA \
      -dname $dname -validity $daysvalid \
      -keypass $keystorepwd -keystore $keystorefile -storepass $keystorepwd

  keytool -export -alias $alias -keystore $keystorefile -storepass $keystorepwd -rfc \
      -file $alias.cer
  keytool -import -noprompt -alias $alias -keystore $bootstrap_keystore -storepass $keystorepwd -file $alias.cer
  rm -f $alias.cer
}

renameAlias() {
  oldalias=$1
  newalias=$2
  keytool -keyclone -v -alias $oldalias -dest $newalias \
     -keystore $keystorefile -storepass $keystorepwd -keypass $keystorepwd -new $keystorepwd
  keytool -delete -v -alias $oldalias -keystore $keystorefile -storepass $keystorepwd
}

renameAliasBootstrapKeystore() {
  oldalias=$1
  newalias=$2
  keytool -export -v -alias $oldalias -file old.cer \
     -keystore $bootstrap_keystore -storepass $keystorepwd -rfc
  keytool -import -noprompt -alias $newalias \
     -keystore $bootstrap_keystore -storepass $keystorepwd -file old.cer
  rm -f old.cer
  keytool -delete -v -alias $oldalias -keystore $bootstrap_keystore -storepass $keystorepwd
}

keyaliases="bootstrapper privileged unprivileged securitymodule"

alias rm rm
for keyalias in $keyaliases ; do
  echo "============ Processing key: $keyalias"
  renameAlias $keyalias $keyalias-old
  renameAliasBootstrapKeystore $keyalias $keyalias-old
  genkey $keyalias "CN=$keyalias,O=Cougaar,C=US"
done

