=begin script

include_path: setup_security.rb
description: special initialization for security

=end


require 'security/lib/scripting'

insert_after :society_running do
  # We set the agent name parameter to "nil", which instructs the
  # action to look for the agent that has "org_id" facet == "OSD.GOV"
  # This makes it easier to run the stresses with the PING society.
  wait_for  "UserManagerReady", nil, "/userManagerReady", 60.minutes
end

