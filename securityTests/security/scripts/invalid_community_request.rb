#
# Security UCx: Invalid JOIN community request
# AgentX is attempting to issue a JOIN request for AgentY
#

require 'security/lib/scripting'
require 'security/lib/stresses/joinCommunity'

insert_before :setup_run do
  do_action  "InjectStress", "JoinCommunity", "setupStress"
end

insert_before :society_running do
  do_action  "InjectStress", "JoinCommunity", "executeStress"
end
