CIP = ENV['CIP'] 
RULES = File.join(CIP, 'csmart','config','rules') 
 
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist') 
$:.unshift File.join(CIP, 'csmart', 'config', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'lib')


# Uncomment the following line if working in the CSI testbed
# I haven't yet fixed the problem that this depends on linux postgres.so
#require 'framework/scripting'


require 'cougaar/scripting' 
require 'cougaar/experiment'
require 'cougaar/communities' 
require 'ultralog/scripting'
require 'ultralog/services' 

require 'security/lib/cougaarMods'
require 'security/actions/cond_policy'
require 'security/lib/misc'
 
require 'socket' 
require 'rexml/document' 

require 'policyInitDM.rb'
 
Cougaar::ExperimentMonitor.enable_stdout 
Cougaar::ExperimentMonitor.enable_logging 
 
Cougaar.new_experiment("Policy-Test").run(1) { 

  layout_file="PolicyOne"
 
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
    "#{RULES}/security",
    "#{RULES}/security/communities"

  # optional: save the society to an XML file for easy debugging 
  do_action "SaveCurrentSociety", "mySociety.xml" 
  do_action "SaveCurrentCommunities", "myCommunities.xml" 


  # start jabber 
  # 
  # replace the last parameter with your jabber server's host name  

  do_action "StartJabberCommunications"
  do_action "VerifyHosts" 

  do_action "DeployCommunitiesFile" 
 
  do_action "StartSociety" 

  do_action "InitDM"
 
  # however long you want to run 
#  do_action "Sleep", 40.minutes 
 
#  do_action "StopSociety" 
#  do_action "StopCommunications" 
} 

