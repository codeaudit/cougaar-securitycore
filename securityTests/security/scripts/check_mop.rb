#
# Security MOPs
#   MOP 2.1: Confidentiality of sensitive data stored in computer memory
#   MOP 2.2: Confidentiality of sensitive data stored on computer disk
#   MOP 2.3: Confidentiality of sensitive data transmitted between computers
#   MOP 2.4: Accountability of user actions invoked within the society
#   MOP 2.5:
#

require 'security/lib/scripting'
require 'security/lib/securityMops'
require 'security/lib/SecurityMop2_4'
require 'security/lib/SecurityMop2_5'
require 'security/lib/SecurityMop2_6'

insert_after :society_running do
  # MOP 2.1: blackboard access control
  do_action  "InjectStress", "SecurityMop21", "setup"
end

insert_after :after_stage_1 do
  # MOP 2.1: blackboard access control
  do_action  "InjectStress", "SecurityMop21", "shutdown"
  do_action  "InjectStress", "SecurityMop21", "calculate"

  # MOP 2.2: encrypted persistence files
  do_action  "InjectStress", "SecurityMop22", "calculate"

  # MOP 2.3: encrypted messages
  do_action  "InjectStress", "SecurityMop23", "calculate"

  # MOP 2.4: unauthorized user actions
  do_action  "InjectStress", "SecurityMop2_4", "calculate"

  # MOP 2.5: user action audit
  do_action  "InjectStress", "SecurityMop2_5", "calculate"

  # MOP 2.5: IDMEF events
  do_action  "InjectStress", "SecurityMop2_6", "calculate"

end

