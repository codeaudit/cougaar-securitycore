#
# Security UC3: Message
#
require 'security/lib/scripting'
require 'security/lib/stresses/sendMessage'

insert_before :society_running do
  # Check: Send message successfully
  do_action  "InjectStress", "Stress3a101", "postConditionalNextOPlanStage"
end

