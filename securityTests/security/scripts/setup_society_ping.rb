
require 'security/lib/scripting'
require 'security/actions/ping_active'

insert_before :wait_for_initialization do
  wait_for  "PingActive", 20.minutes
end
