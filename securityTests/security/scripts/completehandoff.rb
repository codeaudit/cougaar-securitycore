require 'security/lib/scripting'
require 'security/actions/completesecurityhandoff'

insert_after parameters[:start_label] do
  do_action "CompleteSecurityHandOff",parameters[:nodename],parameters[:enclave]
end
