require 'security/lib/scripting'
require 'security/actions/completesecurityhandoff'
require 'security/actions/policyGeneration'

insert_after parameters[:start_label] do
  do_action "MoveNodeGuard", parameters[:nodename], parameters[:enclave]

  do_action "CompleteSecurityHandOff",parameters[:nodename],parameters[:enclave]
end
