#
# Security UC3: Message
#
# Revoke a node
# Revoke an agent

require 'security/lib/scripting'
require 'security/lib/stresses/3c2'

insert_before :setup_run do
  do_action  "InjectStress", "Security3c2", "postStartJabberCommunications"
end

insert_after :during_stage_1 do
  # Revoke a node
  # Revoke an agent
  # in 1k society we have the problem of society still loading at initialization stage
  do_action  "InjectStress", "Security3c2", "postLoadSociety"
end

insert_before :society_running do
  do_action  "InjectStress", "Security3c2", "revokeAgentAndNode"
end
