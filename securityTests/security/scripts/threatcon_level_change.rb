#
# Security UC1: Threatcon level change
#

require 'security/lib/scripting'
require 'security/lib/stresses/threatConChange'

insert_before :setup_run do
  do_action  "InjectStress", "ThreatConChange", "preStartSociety"
end

insert_before :society_running do
  do_action  "InjectStress", "ThreatConChange", "postSocietyQuiesced"
end
