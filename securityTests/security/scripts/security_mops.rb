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

insert_before :society_running do
  do_action "InitiateSecurityMopCollection"
end

#insert_before :stopping_society do
insert_before "FreezeSociety" do
  do_action "StopSecurityMopCollection"
end

insert_before :society_stopped do
#insert_after parameters[:send_security_mop_request_label] do
  do_action "SendSecurityMopRequest"
end
