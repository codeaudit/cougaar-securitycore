

require 'security/actions/policyGeneration.rb'

insert_before :setup_run do
  do_action "BuildURPolicies",
               parameters[:dbUser], 
               parameters[:dbHost],
               parameters[:dbPassword],
               parameters[:db]
end

insert_after parameters[:insertionPoint] do
  do_action "InstallURPolicies", parameters[:wait]
end
