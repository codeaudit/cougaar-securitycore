#
# Security UC5: SECURE EXECUTION ENVIRONMENT
#   Jar file verification

require 'security/lib/stresses/jar_files.rb'


insert_before :wait_for_initialization do
  do_action "InjectStress", "Stress5a1", "postLoadSociety"
  do_action "InjectStress", "Stress5a1", "preConditionalStartSociety"

  do_action "InjectStress", "Stress5a2", "postLoadSociety"
  do_action "InjectStress", "Stress5a2", "preConditionalStartSociety"

  do_action "InjectStress", "Stress5a3", "postLoadSociety"
  do_action "InjectStress", "Stress5a3", "preConditionalStartSociety"

  do_action "InjectStress", "Stress5a4", "postLoadSociety"
  do_action "InjectStress", "Stress5a4", "preConditionalStartSociety"

  do_action "InjectStress", "Stress5a101", "postLoadSociety"
  do_action "InjectStress", "Stress5a101", "preConditionalStartSociety"

  do_action "InjectStress", "Stress5a20", "preConditionalStartSociety"
  do_action "InjectStress", "Stress5a21", "preConditionalStartSociety"
  do_action "InjectStress", "Stress5a22", "preConditionalStartSociety"
  do_action "InjectStress", "Stress5a23", "preConditionalStartSociety"

end

insert_before :society_running do
  do_action "InjectStress", "Stress5a1", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a2", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a3", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a4", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a101", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a20", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a21", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a22", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress5a23", "postConditionalNextOPlanStage"
end

insert_after :after_stage_1 do
  do_action "InjectStress", "Stress5a1", "postStopSociety"
  do_action "InjectStress", "Stress5a2", "postStopSociety"
  do_action "InjectStress", "Stress5a3", "postStopSociety"
  do_action "InjectStress", "Stress5a4", "postStopSociety"
  do_action "InjectStress", "Stress5a101", "postStopSociety"
end
