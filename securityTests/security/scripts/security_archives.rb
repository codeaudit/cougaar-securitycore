#
# Security archives
#

require 'security/lib/scripting'

insert_before :setup_run do
  do_action "MarkForArchive", "#{CIP}/workspace/auditlogs", "*", "Tomcat audit files"
  do_action "MarkForArchive", "#{CIP}/workspace/test", "*", "Security stresses results"
  do_action "MarkForArchive", "#{CIP}/workspace/security/keystores", "*", "Keystore files"
  do_action "MarkForArchive", "#{CIP}/workspace/security/mopresults", "*", "Blackboard access control MOP"
end
