
=begin script

include_path: setup_security.rb
description: special initialization for security

=end

require './ping.rb'

insert_before :transformed_society do

  # add a ping from AgentA to AgentB, and have it generate event 
  # statistics once every 10 seconds 
  #  
  # see the org.cougaar.core.mobility.ping.PingAdderPlugin for 
  # additional options. 
  do_action "AddPing", "AgentA", "AgentB", {'eventMillis' => '10000'}

  # add the ping manager plugins 
  # 
  # A ping manager is required for every agent that contains a 
  # ping adder plugin.  This rule searches for the agents and 
  # adds the manager plugins. 
  # 
  # The "1000" is the time between ping timeout and event checks. 
  # One second is fine for most tests. 
  do_action "SetupPingTimers", 1000

end
