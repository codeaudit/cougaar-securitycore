#!/bin/sh


#cd ~/CSI/polaris/automation/scripts03
#ruby runTestScript.rb 1a ${xmlPolarisConfiguration}

xmlPolarisConfiguration=as-10.4.xml
rundir=~/CSI/polaris/automation/scripts03/security
cp ${xmlPolarisConfiguration} ${rundir}
cd ${rundir}
$CIP/csmart/acme_scripting/bin/p-run.rb JTG-Security-1a.rb ${xmlPolarisConfiguration}
