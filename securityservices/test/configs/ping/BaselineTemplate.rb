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
  host_file = nil 
  host = @hostname unless host 
  Dir.glob(File.join(".", "example-hosts-secureMV.xml")).each do |file| 
    ts = Cougaar::SocietyBuilder.from_xml_file(file).society 
    host_file = file 
  end 
  
  do_action "LayoutSociety", parameters[:layout_file], host_file

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

at :society_running

  # Give some time to run the stresses
  do_action "Sleep", 10.minutes 

at :after_stage_1

  # however long you want to run 
  do_action "Sleep", 30.minutes 
  
  do_action "StopSociety"
  
at :society_stopped

  do_action "CleanupSociety"
  do_action "StopCommunications"
}
