#!/bin/sh

set xmlPolarisConfiguration="as-10.4.xml"
cd ~/CSI/polaris/automationi/scripts03/security/
ruby $CIP/csmart/acme_scripting/bin/p-run.rb JTG-Security-1a.rb ${xmlPolarisConfiguration}
