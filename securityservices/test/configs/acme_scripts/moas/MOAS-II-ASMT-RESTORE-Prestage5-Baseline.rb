=begin experiment

name: MOAS-II-RESTORE-Basline
group: nogroup
type: baseline 
description: MOAS-II-preStage5-Restore-Baseline
script: $CIP/csmart/scripts/definitions/RestoreTemplate.rb
parameters:
  - run_count: 1
  - snapshot_name: $CIP/SAVE-PreStage5.tgz
  - archive_dir: $CIP/Logs
  - stages:
    - 5
  
include_scripts:
  - script: $CIP/csmart/lib/isat/clearLogs.rb
###########################################
# Security include scripts
  # Change Ruby load path - This script must be included if any of the other
  # security include scripts are added.
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  # Scripts add listener which look for Added Persistence manager on a Node 
  # Waits for all Persistence Manager to be ready main persistence Manager and backup Persistence manager  
#  - script: $CIP/csmart/lib/security/scripts/setup_PersistenceManagementReady.rb
#    parameters:
#      - persistence_mgr_watcher_label: society_running
  # Insert a "Wait for user manager ready" action. This action must be called
  # before any other action attempts to access servlets.
  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
    parameters:
      - user_mgr_label: society_running
  # Get stats about cpu load, process size, cpu utilization every 60s,
  # and store the data under $CIP/workspace/test/node_info.log.
  - script: $CIP/csmart/lib/security/scripts/log_node_process_info.rb
  # Logs Message queue details to a log file under $CIP/workspace/test/message_queue_log/nodename.log
#  - script: $CIP/csmart/lib/security/scripts/check_message_queue.rb 
#  - script: $CIP/csmart/lib/security/scripts/setup_society_1000_ua.rb
  # Sanity check: Check every 5 minutes if all agents are registered in the WP.
#  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
  # Sanity check: check that all agents have reported for duty, and quickly
  # identify agents that have not reported for duty. This is helpful for
  # debugging purposes.
#  - script: $CIP/csmart/lib/security/scripts/check_report_chain_ready.rb
  # Test that agent revocation works properly. Revoke an agent, then a node.
  # This test always revokes an agent named MessageAttacker.
#  - script: $CIP/csmart/lib/security/scripts/revoke_agent_and_node_cert.rb
  # This include script is not doing anything for now.
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc1.rb
  # Check that secure messaging works properly.
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc3.rb
  # Test the SecureConfigFinder. This test will create bad jar files
  # (e.g. jar files with revoked cert, expired cert, bad signature,
  # tampered file...) and check that the files in those jar files are not loaded.
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc4.rb
  # Test the Java Security Manager. A malicious plugin attempts to write
  # a file without appropriate privileges, and the Java security manager should
  # reject the request.
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc5.rb
  # Test threatcon level changes: generate bad logins, wait until the threatcon
  # goes up, verify that the security policy is changed, wait until the threatcon
  # goes down when no login failures are applied, then check the security policy
  # is changed again.
#  - script: $CIP/csmart/lib/security/scripts/threatcon_level_change.rb
  # Verify that agent without appropriate privileges cannot perform
  # disallowed community requests.
#  - script: $CIP/csmart/lib/security/scripts/invalid_community_request.rb
# MOP computation
  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
    parameters:
      - calculate_mop_label: after_stage
      - postCalculate_mop_label: end_of_run
  # Generate a output file to store the results of the security sanity checks
  # and security stresses. This file should always be included whenever the
  # security services are enabled.
  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  # Save all acme events in a file. This is useful for debugging purposes.
  - script: $CIP/csmart/lib/security/scripts/saveAcmeEvents.rb
  # Invoke MarkForArchive on all files that should be archived.
  # This script should always be included whenever the security services are
  # enabled.
  - script: $CIP/csmart/lib/security/scripts/security_archives.rb
  # Do some basic security cleanup before the society is loaded.
  # This script should always be included whenever the society is loaded.
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb
    parameters:
      - cleanup_label: snapshot_restored
#
###########################################
  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
#  - script: $CIP/csmart/lib/isat/network_shaping.rb
# This script to be used with robustness, to prevend robustness from 
# doing unintented restarts for RESTORE
#  - script: $CIP/csmart/lib/robustness/mic/prepare_kills.rb
#  - script: $CIP/csmart/lib/robustness/objs/deconfliction.rb
#  - script: $CIP/csmart/assessment/assess/inbound_aggagent_include.rb
#  - script: $CIP/csmart/assessment/assess/outofbound_aggagent_include.rb
#  - script: $CIP/csmart/assessment/assess/cnccalc_include.rb
#    parameters:
#      - run_type: base
#      - description: Stage 5 Baseline
#  - script: $CIP/csmart/assessment/assess/analysis_baseline_cmds.rb
#    parameters:
#      - only_analyze: "moe1,moe3"
#      - baseline_name: base2

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
