#
# Security UC5: SECURE EXECUTION ENVIRONMENT
#   Jar file verification
#   Recovery of the persistence state after agent restart
#   Secure Agent Mobility
#   Secure agent restart
#   Naming Service Protection
#   Security Policy Violation Detection
#   Messaging Policy Violation Detection
#   Bootstrapping of the Cryptographic Keys
#   Agent Identity Certificates
#

require 'security/lib/scripting'
require 'security/lib/stresses/javaPolicy'

insert_before :society_running do
  # Java policy checks
  do_action  "StartScheduledStress", "Stress5f", "postConditionalNextOPlanStage", 0.minute, 10.minute
end

insert_after :after_stage_1 do
  # Java policy checks
  do_action  "StopScheduledStress", "Stress5f", "postConditionalNextOPlanStage"
end
