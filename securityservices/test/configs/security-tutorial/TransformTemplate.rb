require 'cougaar/scripting'
require 'ultralog/scripting'

include Cougaar

$:.unshift File.join(CIP, 'csmart', 'lib')
require 'security/actions/build_config_files'

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging

HOST_FILE="OneNodeHostFile.xml"

Cougaar.new_experiment().run(parameters[:run_count]) {
  set_archive_path parameters[:archive_dir]

  do_action "LoadSocietyFromScript", parameters[:society_file]
 
  host_file = nil 
  Dir.glob(File.join(".", HOST_FILE)).each do |file| 
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
