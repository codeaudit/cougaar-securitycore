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

require 'security/lib/cougaarMods'
require 'security/actions/configFiles'
require 'security/actions/cond_policy'
require 'security/actions/saveEvents'
require 'security/lib/misc'


require 'ultralog/scripting'
require 'ultralog/services' 
 
require 'rexml/document' 
require 'socket' 

require 'policyTests'
 
Cougaar::ExperimentMonitor.enable_stdout 
Cougaar::ExperimentMonitor.enable_logging 
 
Cougaar.new_experiment("Policy-Test").run(1) { 

  layout_file="PolicyOne"
#  layout_file="PolicyTwo"

 
  # read the basic society definition 
  # 
  # also see the "create_society.rb" class, which illustrates how 
  # to create a society from scratch within ruby. 
  do_action "LoadSocietyFromXML", "#{layout_file}.xml" 
 
  # find the "*hosts.xml" layout file 
  # 
  # on the TIC machines this can be replaced with the "HOSTS_FILE" 
  # rule, which looks in the operator directory.  The code below 
  # will work in a stand-alone ACME setup. 

   hosts_file = "hosts.xml"

 
  # transform the basic society to use our host-node layout 
  do_action "LayoutSociety", "#{layout_file}-layout.xml", hosts_file 

  do_action "TransformSociety", false, 
    ".",
    "#{RULES}/isat",
    "#{RULES}/robustness",
    "#{RULES}/security",
    "#{RULES}/security/communities",
    "#{RULES}/security/robustness"

  # optional: save the society to an XML file for easy debugging 
  do_action "SaveCurrentSociety", "mySociety.xml" 
  do_action "SaveCurrentCommunities", "myCommunities.xml" 


  # start jabber 
  # 
  # replace the last parameter with your jabber server's host name  

  do_action "StartJabberCommunications"
  do_action "VerifyHosts" 

  do_action "BuildConfigJarFiles"
  do_action "DeployCommunitiesFile" 

  do_action "SaveAcmeEvents"

  do_action "StartSociety" 
  do_action "Sleep", 30.seconds 
#  do_action "SetPoliciesTest"
  do_action "InitDM"
  do_action "Sleep", 40.seconds
}

