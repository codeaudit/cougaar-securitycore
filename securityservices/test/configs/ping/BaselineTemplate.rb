CIP = ENV['CIP']

require 'cougaar/scripting'
require 'ultralog/scripting'

include Cougaar

HOSTS_FILE = Ultralog::OperatorUtils::HostManager.new.get_hosts_file

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging

Cougaar.new_experiment().run(parameters[:run_count]) {
  set_archive_path parameters[:archive_dir]

  do_action "LoadSocietyFromScript", parameters[:society_file]
  
  # find the "*hosts.xml" layout file 
  # 
  # on the TIC machines this can be replaced with the "HOSTS_FILE" 
  # rule, which looks in the operator directory.  The code below 
  # will work in a stand-alone ACME setup. 
  HOSTS_FILE = nil 
  host = @hostname unless host 
  Dir.glob(File.join(".", "example-hosts-secureMV.xml")).each do |file| 
    ts = Cougaar::SocietyBuilder.from_xml_file(file).society 
    HOSTS_FILE = file 
  end 
  
  do_action "LayoutSociety", parameters[:layout_file], HOSTS_FILE

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

  do_action "TransformSociety", false, *parameters[:rules]
  if (!parameters[:community_rules].nil?)
    do_action "TransformSociety", false, *parameters[:community_rules]
  end

at :transformed_society

  do_action "SaveCurrentSociety", "mySociety.xml"
  do_action 'SaveCurrentCommunities', 'myCommunity.xml'

  do_action "StartCommunications"

  do_action "CleanupSociety"
  do_action "Sleep", 10.seconds

  do_action "VerifyHosts"

  do_action "DeployCommunitiesFile"
  
  # optional: print the cougaar events 
  # 
  # this will also print the ping statistics events 
  do_action "GenericAction" do |run| 
     run.comms.on_cougaar_event do |event| 
       puts event 
     end 
  end 
  
at :setup_run

  do_action "StartSociety"

at :wait_for_initialization

  # however long you want to run 
  do_action "Sleep", 40.minutes 
  
at :society_running
  
  do_action "StopSociety"
  
at :society_stopped

  do_action "CleanupSociety"
  do_action "StopCommunications"
}
