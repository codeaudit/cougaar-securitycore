
require 'security/lib/scripting'
require 'security/actions/ping_active'
require 'security/lib/security'
require 'security/actions/buildHostFile'
require 'security/actions/build_config_files'
require 'security/actions/resetCsiAcme'

insert_before "build_host_file" do
  do_action "BuildCsiHostFile", "host-layout-file.xml"
  do_action "ResetCsiAcme"
  do_action "Sleep", 5.seconds
end

PingSociety.setPingSociety
insert_before :wait_for_initialization do
  wait_for  "PingActive", 20.minutes
end

insert_before :setup_run do
  # Replacing DeployCommunitiesFile which does not work at CSI's testbed
  do_action "BuildSignedCommunityJarFile", "myCommunity.xml", "#{CIP}/configs/common"
end
