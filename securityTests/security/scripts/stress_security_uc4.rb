
# Security use case 4
#
#

require 'security/lib/scripting'
require 'security/lib/stresses/jar_files.rb'

insert_before :wait_for_initialization do
  do_action "InjectStress", "Stress4a50", "buildConfigFile"
  do_action "InjectStress", "Stress4a50", "postLoadSociety"
  do_action "InjectStress", "Stress4a50", "preConditionalStartSociety"

  do_action "InjectStress", "Stress4a51", "buildConfigFile"
  do_action "InjectStress", "Stress4a51", "postLoadSociety"
  do_action "InjectStress", "Stress4a51", "preConditionalStartSociety"

  do_action "InjectStress", "Stress4a52", "buildConfigFile"
  do_action "InjectStress", "Stress4a52", "postLoadSociety"
  do_action "InjectStress", "Stress4a52", "preConditionalStartSociety"

  do_action "InjectStress", "Stress4a53", "buildConfigFile"
  do_action "InjectStress", "Stress4a53", "postLoadSociety"
  do_action "InjectStress", "Stress4a53", "preConditionalStartSociety"

  do_action "InjectStress", "Stress4a201", "buildConfigFile"
  do_action "InjectStress", "Stress4a201", "postLoadSociety"
  do_action "InjectStress", "Stress4a201", "preConditionalStartSociety"

  do_action "InjectStress", "Stress4a60", "preConditionalStartSociety"
  do_action "InjectStress", "Stress4a61", "preConditionalStartSociety"
  do_action "InjectStress", "Stress4a62", "preConditionalStartSociety"
  do_action "InjectStress", "Stress4a63", "preConditionalStartSociety"
end

insert_before :society_running do
  do_action "InjectStress", "Stress4a50", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a51", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a52", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a53", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a201", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a60", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a61", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a62", "postConditionalNextOPlanStage"
  do_action "InjectStress", "Stress4a63", "postConditionalNextOPlanStage"
end

insert_after :society_stopped do
  do_action "InjectStress", "Stress4a50", "postStopSociety"
  do_action "InjectStress", "Stress4a51", "postStopSociety"
  do_action "InjectStress", "Stress4a52", "postStopSociety"
  do_action "InjectStress", "Stress4a53", "postStopSociety"
  do_action "InjectStress", "Stress4a201", "postStopSociety"
end

