require 'security/lib/scripting'
require 'security/actions/policyGeneration'

insert_before parameters[:start_label] do
  do_action "InstallBootPolicies", parameters[:wait_flag]
end
