require 'security/lib/scripting'
require 'security/actions/startsecurityhandoff'
require 'security/actions/policyGeneration'

insert_after parameters[:start_label] do

  #do_action "MigratePolicies",parameters[:nodename],parameters[:enclave]

  do_action "StartSecurityHandOff",parameters[:nodename]

end
