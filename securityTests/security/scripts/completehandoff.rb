require 'security/lib/scripting'
require 'security/actions/completesecurityhandoff'

insert_before parameters[:start_label] do
  do_action "CompleteSecurityHandOff",parameters[:nodename],parameters[:enclave]
end
