require 'security/lib/scripting'
require 'security/actions/installBootPolicies'

insert_after parameters[:insertionPoint] do
  do_action "InstallBootPolicies"
end
