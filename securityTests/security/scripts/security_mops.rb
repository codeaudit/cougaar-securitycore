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

insert_before :setup_run do
  if PingSociety.isPingSociety 
    do_action "StartTcpCapture", ["AgentA", "AgentB"]
  else
    do_action "StartTcpCapture", ["ConusSea.TRANSCOM.MIL", "FORSCOM.MIL", "OSD.GOV", "RearEnclaveCaManager", "RearUserAdminAgent", "11-AVN-RGT.5-CORPS.ARMY.MIL"]
  end
end

insert_after :society_running do
  do_action "InitiateSecurityMopCollection"
end

insert_after :society_stopping do
  do_action "StopSecurityMopCollection"
end

insert_after :society_stopped do
  do_action "SendSecurityMopRequest"
end
