
require 'security/lib/scripting'
require 'security/actions/saveEvents'

insert_before :wait_for_initialization do
  do_action  "SaveAcmeEvents"
end
