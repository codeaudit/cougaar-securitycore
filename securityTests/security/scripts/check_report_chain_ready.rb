
require 'security/lib/scripting'
require 'security/lib/stresses/reportChainReady'

insert_before :setup_run do
   do_action "InjectStress", "TestReportChainReady", "beforeStartedSociety"
end

insert_before :society_running do
   do_action "InjectStress", "TestReportChainReady", "afterReportChainReady"
end
