require 'cougaar/scripting'
require 'ultralog/scripting'

include Cougaar

HOSTS_FILE = Ultralog::OperatorUtils::HostManager.new.get_hosts_file
#puts "Host file #{HOSTS_FILE}"

#CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'lib')
require 'security/actions/buildHostFile'
require 'security/actions/build_config_files'

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
  host_file = HOSTS_FILE
  #host = @hostname unless host 

  do_action "BuildCsiHostFile", "host-layout-file.xml"

  Dir.glob(File.join(".", "host-layout-file.xml")).each do |file| 
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

  do_action "BuildSignedCommunityJarFile", "myCommunity.xml"
  do_action "BuildSignedNodeJarFiles"
}
