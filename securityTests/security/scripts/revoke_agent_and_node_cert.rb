#
# Security UC3: Message
#
# Revoke a node
# Revoke an agent

require 'security/lib/scripting'
require 'security/lib/stresses/javaPolicy'

insert_before :setup_run do
  do_action  "InjectStress", "Security3c2", "postStartJabberCommunications"
end

insert_before :wait_for_initialization do
  # Revoke a node
  # Revoke an agent
  do_action  "InjectStress", "Security3c2", "postLoadSociety"
end

insert_before :society_running do
  do_action  "InjectStress", "Security3c2", "postConditionalGLSConnection"
end
