

require 'security/actions/policyGeneration.rb'

insert_before :setup_run do
  do_action "BuildURPolicies"
end

insert_after :wait_for_initialization do
  do_action "InstallURPolicies"
end
