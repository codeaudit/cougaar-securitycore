#!/bin/sh

set xmlPolarisConfiguration="as-10.4.xml"
cd ~/CSI/polaris/automationi/scripts03/security/
ruby ../runTestScript.rb 1a ${xmlPolarisConfiguration}
