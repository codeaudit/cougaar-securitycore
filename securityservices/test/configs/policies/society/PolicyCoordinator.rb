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

require 'security/actions/saveEvents'
require 'security/lib/cougaarMods'
require 'security/actions/buildCoordinatorPolicies'
require 'security/actions/buildUserFiles'
require 'security/actions/configFiles'
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


  society_file="PolicyCoordinator.xml"
  layout_file="PolicyOne-layout.xml"
# layout_file="PolicyTwo-layout.xml"
# layout_file="PolicyTwoSpread-layout.xml"

 
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

 
  # transform the basic society to use our host-node layout 
  do_action "LayoutSociety", "#{layout_file}", hosts_file 

  do_action "TransformSociety", false, 
    ".",
    "#{RULES}/isat",
    "#{RULES}/security",
    "#{RULES}/security/communities",
    "#{RULES}/security/mop/audit_servlet.rule",
    "#{RULES}/security/robustness",
    "#{RULES}/security/mts/loopback_protocol.rule",
    "#{RULES}/security/mts/sslRMI.rule",
    "#{RULES}/security/mts/http_mts.rule",
#    "#{RULES}/security/mts/https_mts.rule",
    "#{RULES}/security/naming",
    "#{RULES}/security/test/test-network-config.rule"


    "#{CIP}/csmart/lib/security/rules/mts_queue_viewer.rule"

  # optional: save the society to an XML file for easy debugging 
  do_action "SaveCurrentSociety", "mySociety.xml" 
  do_action "SaveCurrentSociety", "mySociety.rb" 
  do_action "SaveCurrentCommunities", "myCommunities.xml" 


  # start jabber 
  # 
  # replace the last parameter with your jabber server's host name  

  do_action "StartCommunications"
  do_action "VerifyHosts" 

  do_action "BuildConfigJarFiles"
  do_action "BuildPolicies"
  do_action "BuildCoordinatorPolicies"
  do_action "BuildUserFiles"  
  do_action "DeployCommunitiesFile" 

  do_action "StartSociety" 

  do_action "Sleep", 30.seconds 
  do_action "WaitForUserManagerReady"
  
  do_action "GenericAction" do |myRun|
# use @run for the run variable here - myRun and run doesn't work.
# to reference one of the classes from policyTests use the following syntax:
#   ::Cougaar::Actions::BlackboardTest.new(@run)
    load 'debug.rb'
  end

}

