
require 'security/lib/scripting'
require 'security/lib/stresses/reportChainReady'

insert_after :setup_run do
   do_action "InjectStress", "TestReportChainReady", "beforeStartedSociety"
end

insert_after :society_running do
   do_action "InjectStress", "TestReportChainReady", "afterReportChainReady"
end
