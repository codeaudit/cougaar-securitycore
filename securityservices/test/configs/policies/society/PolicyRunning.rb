#!/usr/bin/ruby

CIP = ENV['CIP'] 
RULES = File.join(CIP, 'csmart','config','rules') 
 
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist') 
$:.unshift File.join(CIP, 'csmart', 'config', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting' 

require 'cougaar/communities' 
require 'cougaar/experiment'

require 'security/actions/cond_policy'
require 'security/actions/configFiles'
require 'security/actions/saveEvents'
require 'security/lib/cougaarMods'
require 'security/actions/configFiles'
require 'security/actions/cond_policy'
require 'security/actions/saveEvents'
require 'security/scripts/setup_scripting'
require 'security/actions/inject_stress'
require 'security/lib/misc'


require 'ultralog/scripting'
require 'ultralog/services' 
 
require 'rexml/document' 
require 'socket' 

require 'policyTests'
 
Cougaar::ExperimentMonitor.enable_stdout 
Cougaar::ExperimentMonitor.enable_logging 
 
Cougaar.new_experiment("Policy-Test").run(1) { 
  do_action "LoadSocietyFromScript", 
            "mySociety.rb"
  do_action "StartJabberCommunications"


  do_action "CommunicationTest01"
#  do_action "ServletTests"
  do_action "CommunicationTest01"
#  do_action "DomainManagerRehydrateReset"

}
