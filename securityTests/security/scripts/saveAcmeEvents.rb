
require 'security/lib/scripting'
require 'security/actions/saveEvents'

insert_after :setup_run do
  do_action  "SaveAcmeEvents"
end
