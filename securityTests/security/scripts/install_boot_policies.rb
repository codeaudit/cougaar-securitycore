require 'security/lib/scripting'
require 'security/actions/installBootPolicies'

insert_after parameters[:start_label] do
  do_action "InstallBootPolicies"
end
