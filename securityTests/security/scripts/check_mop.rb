#
# Security MOPs
#   MOP 2.1: Confidentiality of sensitive data stored in computer memory
#   MOP 2.2: Confidentiality of sensitive data stored on computer disk
#   MOP 2.3: Confidentiality of sensitive data transmitted between computers
#   MOP 2.4: Accountability of user actions invoked within the society
#   MOP 2.5:
#

require 'security/lib/scripting'
require 'security/lib/stresses/blackboardAccessControl'

insert_after :society_running do
  do_action  "InjectStress", "Stress1d", "postPublishNextStage"
end

insert_after :after_stage_1 do
  do_action  "InjectStress", "Stress1d", "preSocietyQuiesced"
  do_action  "InjectStress", "Stress1d", "compileResults"

#  do_action "InitiateSecurityMopCollection"

#  do_action "StopSecurityMopCollection"
#  do_action "SendSecurityMopRequest"

end

