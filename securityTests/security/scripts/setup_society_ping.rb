
require 'security/lib/scripting'
require 'security/actions/ping_active'
require 'security/lib/security'
require 'security/actions/buildHostFile'
require 'security/actions/resetCsiAcme'

insert_before "build_host_file" do
  do_action "BuildCsiHostFile", "example-hosts-secureMV.xml"
  do_action "ResetCsiAcme"
  do_action "Sleep", 5.seconds
end

PingSociety.setPingSociety
insert_before :wait_for_initialization do
  wait_for  "PingActive", 20.minutes
end
