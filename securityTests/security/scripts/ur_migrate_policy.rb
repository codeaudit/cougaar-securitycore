

require 'security/actions/policyGeneration.rb'

insert_before parameters[:migrate_location] do
  do_action "MigratePolicies", parameters[:node_name],parameters[:target_network]
end
