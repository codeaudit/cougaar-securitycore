
#
# Security UC2: M&R

require 'security/lib/scripting'
require 'security/lib/stresses/registration'

insert_before :wait_for_initialization do
  do_action  "InjectStress", "Stress2f102", "preConditionalStartSociety"
end

insert_before :society_running do
  do_action  "InjectStress", "Stress2f102", "postConditionalNextOPlanStage"
end

insert_before :after_stage_1 do
  do_action  "InjectStress", "Stress2f102", "preStopSociety"
end
