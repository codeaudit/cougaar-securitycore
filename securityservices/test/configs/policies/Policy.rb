CIP = ENV['CIP'] 
RULES = File.join(CIP, 'csmart','config','rules') 
 
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist') 
$:.unshift File.join(CIP, 'csmart', 'config', 'lib') 

# Uncomment the following two lines if working in the CSI testbed
#$:.unshift File.join(CIP, 'csmart', 'assessment', 'lib') 
#require 'framework/scripting'
 
require 'cougaar/scripting' 
require 'cougaar/communities' 
require 'ultralog/scripting'
require 'ultralog/services' 
 
require 'socket' 
require 'rexml/document' 
 
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

 # hosts_file = File.join(CIP, 'configs', 'ping', 'hosts.xml')
   hosts_file = "hosts.xml"

#  hosts_file = nil 
#  host = @hostname unless host 
#  Dir.glob(File.join(".", "*hosts.xml")).each do |file| 
#    ts = Cougaar::SocietyBuilder.from_xml_file(file).society 
#    hosts_file = file 
#  end 
 
  # transform the basic society to use our host-node layout 
  do_action "LayoutSociety", "#{layout_file}-layout.xml", hosts_file 
 
 
  # load local rules (ping_env.rule) 
  do_action "TransformSociety", false, 
    ".", 
    "#{RULES}/isat/nameserver.rule",
    "#{RULES}/isat/default_servlets.rule",
    "#{RULES}/isat/root_mobility_plugin.rule",
    "#{RULES}/isat/logging_config_servlet.rule",
    "#{RULES}/isat/community_plugin.rule",
    "#{RULES}/isat/show_jars.rule",
#    "#{RULES}/isat/tic_env.rule",
#    "#{RULES}/isat",
    "#{RULES}/security"

 
  # Build the communities.xml file 
  do_action "TransformSociety", false, 
    "#{RULES}/security/communities" 
 
  # optional: save the society to an XML file for easy debugging 
  do_action "SaveCurrentSociety", "mySociety.xml" 
  do_action "SaveCurrentCommunities", "myCommunities.xml" 

  # Uncomment the following line if working in the CSI testbed
  #  do_action "SetAcmeUser" 

  # start jabber 
  # 
  # replace the last parameter with your jabber server's host name  
  do_action "StartJabberCommunications"
  do_action "CleanupSociety"
#  do_action "VerifyHosts" 
  do_action "ConnectOperatorService"
  do_action "ClearPersistenceAndLogs"
  do_action "GenericAction" do 
    `rm -rf #{CIP}/workspace`
  end
  do_action "DeployCommunitiesFile" 
 
  # optional: print the cougaar events 
  # 
  # this will also print the ping statistics events 
#  do_action "GenericAction" do |run| 
#     run.comms.on_cougaar_event do |event| 
#       puts event 
#     end 
#  end 
 
  do_action "CleanupSociety" 
 
  do_action "StartSociety" 
 
  # however long you want to run 
  do_action "Sleep", 40.minutes 
 
  do_action "StopSociety" 
  do_action "StopCommunications" 
} 

