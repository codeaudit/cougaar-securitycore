#!/bin/sh

# Replace u180 in p-config.rb script
#
if [ ! -f $CIP/csmart/acme_scripting/bin/p-config.rb.ori ]; then
  mv $CIP/csmart/acme_scripting/bin/p-config.rb $CIP/csmart/acme_scripting/bin/p-config.rb.ori
fi
sed -e s/\"u180/\"polaris.ultralog.net/ $CIP/csmart/acme_scripting/bin/p-config.rb.ori > \
   $CIP/csmart/acme_scripting/bin/p-config.rb

xmlPolarisConfiguration=as-10.4.xml
rundir=~/CSI/polaris/automation/scripts03/security
cp ${xmlPolarisConfiguration} ${rundir}
cd ${rundir}
#$CIP/csmart/acme_scripting/bin/p-run.rb JTG-Security-1a.rb ${xmlPolarisConfiguration}
$CIP/csmart/acme_scripting/bin/p-run.rb JTG-Security-3a101.rb ${xmlPolarisConfiguration}
