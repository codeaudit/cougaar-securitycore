require 'cougaar/scripting'
require 'ultralog/scripting'

$:.unshift File.join(CIP, 'csmart', 'lib')
require 'security/lib/scripting'
require 'security/lib/security'
require 'security/actions/buildHostFile'
require 'security/actions/build_config_files'
require 'security/actions/resetCsiAcme'

include Cougaar

HOSTS_FILE = Ultralog::OperatorUtils::HostManager.new.get_hosts_file
#puts "Host file #{HOSTS_FILE}"

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

  do_action "BuildCsiHostFile", "host-layout-file.xml"
  do_action "ResetCsiAcme"

}
