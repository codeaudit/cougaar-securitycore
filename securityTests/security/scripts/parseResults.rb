
require 'security/lib/scripting'
require 'security/actions/parseResults'

insert_before :setup_run do
  do_action  "LogPlannedSecurityExperiments"
end

insert_after :society_stopped do
  do_action  "ParseSecurityResults"
end
