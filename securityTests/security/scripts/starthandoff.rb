require 'security/lib/scripting'
require 'security/actions/startsecurityhandoff'

insert_before parameters[:start_label] do
  do_action "StartSecurityHandOff",parameters[:nodename]
end
