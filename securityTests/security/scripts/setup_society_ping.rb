
require 'security/lib/scripting'
require 'security/actions/ping_active'
require 'security/lib/security'

PingSociety.setPingSociety
insert_before :wait_for_initialization do
  wait_for  "PingActive", 20.minutes
end
