CIP = ENV['CIP'] 
RULES = File.join(CIP, 'csmart','config','rules') 
 
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib') 
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist') 
$:.unshift File.join(CIP, 'csmart', 'config', 'lib') 
 
require 'cougaar/scripting' 
#require './create_society.rb' 
require './ping.rb' 
require './wp_protection.rb'
require 'cougaar/communities' 
require 'ultralog/services' 
 
require 'socket' 
require 'rexml/document' 
 
Cougaar::ExperimentMonitor.enable_stdout 
Cougaar::ExperimentMonitor.enable_logging 
 
Cougaar.new_experiment("WP-SecureMiniPing-Test").run(1) { 
 
  # read the basic society definition 
  # 
  # also see the "create_society.rb" class, which illustrates how 
  # to create a society from scratch within ruby. 
  do_action "LoadSocietyFromXML", "MiniPing.xml" 
 
  # find the "*hosts.xml" layout file 
  # 
  # on the TIC machines this can be replaced with the "HOSTS_FILE" 
  # rule, which looks in the operator directory.  The code below 
  # will work in a stand-alone ACME setup. 
  hosts_file = File.join(CIP, 'configs', 'ping-wp', 'wp-hosts.xml')
  #host = @hostname unless host 
  #Dir.glob(File.join(".", "*hosts.xml")).each do |file| 
    #ts = Cougaar::SocietyBuilder.from_xml_file(file).society 
    #hosts_file = file 
  #end 
 
  # transform the basic society to use our host-node layout 
  do_action "LayoutSociety", "wp-layout.xml", hosts_file 
 
  # add the community plugins 
  do_action "SetupCommunityPlugins" 
 
  # add a ping from AgentA to AgentB, and have it generate event 
  # statistics once every 10 seconds 
  #  
  # see the org.cougaar.core.mobility.ping.PingAdderPlugin for 
  # additional options. 
  do_action "AddPing", "AgentA", "AgentB", {'eventMillis' => '10000'} 
 
  # add the ping manager plugins 
  # 
  # A ping manager is required for every agent that contains a 
  # ping adder plugin.  This rule searches for the agents and 
  # adds the manager plugins. 
  # 
  # The "1000" is the time between ping timeout and event checks. 
  # One second is fine for most tests. 
  do_action "SetupPingTimers", 1000 

  # set up WP protection
  do_action "AddWPProtection"
  do_action "AddWPTest", "AgentA", "GOOD"
  do_action "AddWPTest", "AgentB", "BAD" 
 
  # load local rules (ping_env.rule) 
  do_action "TransformSociety", false, ".", 
    "#{RULES}/isat/nameserver.rule",
    "#{RULES}/isat/default_servlets.rule",
    "#{RULES}/isat/root_mobility_plugin.rule",
    "#{RULES}/isat/logging_config_servlet.rule",
    "#{RULES}/isat/community_plugin.rule",
    "#{RULES}/isat/show_jars.rule",
    "#{RULES}/isat/tic_env.rule",
#   "#{RULES}/isat",
    "#{RULES}/security" 
 
  # Build the communities.xml file 
  do_action "TransformSociety", false, 
    "#{RULES}/security/community" 
 
  # optional: save the society to an XML file for easy debugging 
  do_action "SaveCurrentSociety", "wpSociety.xml" 
  do_action "SaveCurrentCommunities", "wpCommunities.xml" 
 
  # start jabber 
  # 
  # replace the last parameter with your jabber server's host name  
  do_action "StartJabberCommunications", "acme_console", "puma3" 
 
  do_action "DeployCommunitiesFile" 
 
  do_action "VerifyHosts" 
 
  # optional: print the cougaar events 
  # 
  # this will also print the ping statistics events 
  do_action "GenericAction" do |run| 
     run.comms.on_cougaar_event do |event| 
       puts event 
     end 
  end 
 
  #do_action "CleanupSociety" 
 
  do_action "StartSociety" 
 
  # however long you want to run 
  # do_action "Sleep", 8.minutes 

  wait_for "Command", "shutdown" 
  do_action "StopSociety" 
  do_action "StopCommunications" 
} 

