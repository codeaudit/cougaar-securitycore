#
# Security archives
#

require 'security/lib/scripting'
require 'security/actions/archive_setup'

insert_before :setup_run do
  # Create the archive directories if they do not exist yet
  do_action "SecurityArchiveSetup"

  do_action "MarkForArchive", "#{CIP}/workspace/auditlogs", "*", "Tomcat audit files"
  do_action "MarkForArchive", "#{CIP}/workspace/test", "*", "Security stresses results"
  do_action "MarkForArchive", "#{CIP}/workspace/test/stacktraces", "*.log", "Security stresses results"
  do_action "MarkForArchive", "#{CIP}/workspace/security/keystores", "*", "Keystore files"
  do_action "MarkForArchive", "#{CIP}/workspace/security/mopresults", "*", "Blackboard access control MOP"
end
