#!/usr/bin/ruby

CIP = ENV['CIP'] 

$:.unshift File.join(CIP, 'csmart', 'config', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'lib')

$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist') 

if File.exist?("#{CIP}/acme")
  # Below is the path when using open-source ACME
  $:.unshift File.join(CIP, 'acme', 'acme_scripting',  'src', 'lib')
  $:.unshift File.join(CIP, 'acme', 'acme_service', 'src', 'redist')
  require 'cougaar/scripting'
  require 'security/actions/cleanup_society'
else 
  require 'cougaar/scripting'
end

require 'cougaar/communities' 
require 'cougaar/experiment'

require 'security/actions/saveEvents'
require 'security/lib/cougaarMods'
require 'security/actions/buildPolicies'
require 'security/actions/buildCoordinatorPolicies'
require 'security/actions/buildUserFiles'
require 'security/actions/build_config_files'
require 'security/actions/configFiles'
require 'security/actions/installBootPolicies'
require 'security/actions/saveEvents'
require 'security/actions/cond_policy'
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


   society_file="PolicyOne.xml"
   layout_file="PolicyOne-layout.xml"

#  society_file="PolicyTwo.xml"
#  layout_file="PolicyTwo-layout.xml"
#  layout_file="PolicyTwoSpread-layout.xml"

 
  # read the basic society definition 
  # 
  # also see the "create_society.rb" class, which illustrates how 
  # to create a society from scratch within ruby. 
  do_action "LoadSocietyFromXML", "#{society_file}" 
 
  # find the "*hosts.xml" layout file 
  # 
  # on the TIC machines this can be replaced with the "HOSTS_FILE" 
  # rule, which looks in the operator directory.  The code below 
  # will work in a stand-alone ACME setup. 

   hosts_file = "hosts.xml"

RULES = File.join(CIP, 'csmart','config','rules') 

 
  # transform the basic society to use our host-node layout 
  do_action "LayoutSociety", "#{layout_file}", hosts_file 

  do_action "TransformSociety", false,
    ".",
    "#{CIP}/csmart/config/rules/isat",
    "#{CIP}/csmart/config/rules/security",
#    "#{CIP}/csmart/config/rules/security/communities",
    "#{CIP}/csmart/config/rules/security/mop/audit_servlet.rule",
    "#{CIP}/csmart/config/rules/security/robustness",
    "#{CIP}/csmart/config/rules/security/testCollectData/MessageReaderAspect.rule",

    "#{CIP}/csmart/config/rules/security/mts/loopback_protocol.rule",
    "#{CIP}/csmart/config/rules/security/mts/sslRMI.rule",
#    "#{CIP}/csmart/config/rules/security/mts/http_mts.rule",
#    "#{CIP}/csmart/config/rules/security/mts/https_mts.rule",
    "#{CIP}/csmart/config/rules/security/naming",
    "#{CIP}/csmart/lib/security/rules/mts_queue_viewer.rule"

  do_action "TransformSociety", false,
    "#{CIP}/csmart/config/rules/security/communities"

  # optional: save the society to an XML file for easy debugging 
  do_action "SaveCurrentSociety", "mySociety.xml" 
  do_action "SaveCurrentSociety", "mySociety.rb" 
  do_action "SaveCurrentCommunities", "myCommunity.xml" 

  do_action "StartCommunications"
  do_action "VerifyHosts" 

  do_action "BuildConfigJarFiles"
  do_action "BuildPolicies"
  do_action "BuildUserFiles"  
  do_action "BuildSignedCommunityJarFile", "myCommunity.xml", 
                                           "#{CIP}/configs/common"
  do_action "StartSociety" 

  do_action "Sleep", 30.seconds 
  do_action "WaitForUserManagerReady"
  
  do_action "InstallBootPolicies"


  do_action "BlackboardTest"
  do_action "ServletTest01"
  do_action "CommunicationTest01"
  do_action "CommunicationTest02"
  do_action "DomainManagerRehydrateReset"
  do_action "TestResults"


}

