require 'security/lib/scripting'
require 'security/lib/LogMessageQueue'

insert_before :wait_for_initialization do
  
  do_action  "LogMessageQueue"
  
end
