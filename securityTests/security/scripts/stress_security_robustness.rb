require 'security/lib/scripting'
require 'security/lib/stresses/4a104'
require 'security/lib/stresses/4a1'

insert_after :setup_run do
  do_action "InjectStress", "Security4a1Experiment", "postStartJabberCommunications"
end

insert_after :after_stage_1 do
  do_action "InjectStress", "Security4a104Experiment", "postPublishNextStage"
  do_action "InjectStress", "Security4b104Experiment", "postPublishNextStage"
  do_action "InjectStress", "Security4a1Experiment", "postPublishNextStage"
end

