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

insert_after :society_running do
  do_action  "InjectStress", "SecurityMop21", "setup"
end

insert_after :after_stage_1 do
  do_action  "InjectStress", "SecurityMop21", "shutdown"
  do_action  "InjectStress", "SecurityMop21", "calculate"

end

