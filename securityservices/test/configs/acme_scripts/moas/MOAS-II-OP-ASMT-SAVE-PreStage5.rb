=begin experiment

name: MOAS-II-AS-Save
description: MOAS-II-AS save pre-Stage5
script: $CIP/csmart/scripts/definitions/BaselineTemplate-ExtOplan.rb
parameters:
  - run_count: 1
  - society_file: $CIP/csmart/config/societies/ua/full-tc20-232a703v.plugins.rb
  - layout_file: $CIP/operator/layouts/04-OP-layout.xml
  - archive_dir: $CIP/Logs

  - rules:
    - $CIP/csmart/config/rules/isat
#    - $CIP/csmart/config/rules/isat/uc3_nosec
    - $CIP/csmart/config/rules/yp
    - $CIP/csmart/config/rules/logistics
    - $CIP/csmart/config/rules/assessment
###########################################
# Security rules
    # Rules to enable the security services.
    - $CIP/csmart/config/rules/security.
    # Rules to add components that apply security stresses.
    # This rule must be added if security include scripts are added to the experiment
    # (see script section below).
    - $CIP/csmart/lib/security/rules
    # Rules that add components to compute the MOP values.
    # These rules must be added if the $CIP/csmart/lib/security/scripts/check_mop.rb
    # script is included (see script section below).
    # In particular, the rules add the blackboard access control components
    - $CIP/csmart/config/rules/security/mop
    # Sanity check: Rule used to check that all agents are reporting for duty.
    - $CIP/csmart/config/rules/security/testCollectData/ServiceContractPlugin.rule
    # Rules to enable the redundant CA and redundant persistence managers.
    # This allows the society to recover from situations where one CA or one PM dies.
    # This rule will search for facets to locate the hosts where redundant CAs and PMs
    # will be installed.
    - $CIP/csmart/config/rules/security/robustness
    # If the redundant CA/PM rule above is added, and there are no redundant facets,
    # then the following rule will add facets automatically.
    # This rule should be enabled only if the layout does not include the redundant CA and PM facets
#    - $CIP/csmart/config/rules/security/redundancy
    # Enable the rules below to enable the redundant PMs but not the redundant CAs
#    - $CIP/csmart/config/rules/security/redundancy/add_redundant_pm_facet.rule
#    - $CIP/csmart/config/rules/security/redundancy/adjust_memory.rule
#    - $CIP/csmart/config/rules/security/robustness/redundant_persistence_mgrs.rule
###########################################
# Robustness rules
# Adding robustness manager agents
#    - $CIP/csmart/config/rules/robustness/manager.rule
# Restarting agents if they are not responding
#    - $CIP/csmart/config/rules/robustness/uc1
# Planned disconnect
#    - $CIP/csmart/config/rules/robustness/uc7
#    - $CIP/csmart/config/rules/robustness/uc9
#    - $CIP/csmart/config/rules/robustness/UC3
#    - $CIP/csmart/config/rules/metrics/basic
#    - $CIP/csmart/config/rules/metrics/sensors
#    - $CIP/csmart/config/rules/metrics/serialization/metrics-only-serialization.rule
#    - $CIP/csmart/config/rules/metrics/rss/tic

#    - $CIP/csmart/config/rules/robustness/uc1/debug/mic.rule
#    - $CIP/csmart/config/rules/robustness/uc1/tuning/collect_stats.rule

  - community_rules:
    - $CIP/csmart/config/rules/security/communities
#    - $CIP/csmart/config/rules/robustness/communities

include_scripts:
  - script: $CIP/csmart/lib/isat/clearPnLogs.rb
###########################################
# Security include scripts
  # Change Ruby load path - This script must be included if any of the other
  # security include scripts are added.
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  # Insert a "Wait for user manager ready" action. This action must be called
  # before any other action attempts to access servlets.
  - script: $CIP/csmart/lib/security/scripts/setup_userManagementSAVE.rb
  # Get stats about cpu load, process size, cpu utilization every 60s,
  # and store the data under $CIP/workspace/test/node_info.log.
  - script: $CIP/csmart/lib/security/scripts/log_node_process_info.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_society_1000_ua.rb
  # Sanity check: Check every 5 minutes if all agents are registered in the WP.
  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
  # Sanity check: check that all agents have reported for duty, and quickly
  # identify agents that have not reported for duty. This is helpful for
  # debugging purposes.
  - script: $CIP/csmart/lib/security/scripts/check_report_chain_ready.rb
  # Test that agent revocation works properly. Revoke an agent, then a node.
  # This test always revokes an agent named MessageAttacker.
  - script: $CIP/csmart/lib/security/scripts/revoke_agent_and_node_cert.rb
  # This include script is not doing anything for now.
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc1.rb
  # Check that secure messaging works properly.
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc3.rb
  # Test the SecureConfigFinder. This test will create bad jar files
  # (e.g. jar files with revoked cert, expired cert, bad signature,
  # tampered file...) and check that the files in those jar files are not loaded.
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc4.rb
  # Test the Java Security Manager. A malicious plugin attempts to write
  # a file without appropriate privileges, and the Java security manager should
  # reject the request.
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc5.rb
  # Test threatcon level changes: generate bad logins, wait until the threatcon
  # goes up, verify that the security policy is changed, wait until the threatcon
  # goes down when no login failures are applied, then check the security policy
  # is changed again.
  - script: $CIP/csmart/lib/security/scripts/threatcon_level_change.rb
  # Verify that agent without appropriate privileges cannot perform
  # disallowed community requests.
  - script: $CIP/csmart/lib/security/scripts/invalid_community_request.rb
# MOP computation
  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
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
#
###########################################
# ISAT scripts
  - script: $CIP/csmart/lib/isat/network_shaping.rb
  - script: $CIP/csmart/lib/isat/klink_reporting.rb
###########################################
# Robustness include scripts
#  - script: $CIP/csmart/lib/robustness/objs/deconfliction.rb
###########################################
# Assessment include scripts
  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
  - script: $CIP/csmart/assessment/assess/inbound_aggagent_include.rb
  - script: $CIP/csmart/assessment/assess/outofbound_aggagent_include.rb
#  - script: $CIP/csmart/assessment/assess/cnccalc_include.rb
###########################################
  - script: $CIP/csmart/lib/isat/save_snapshot.rb
    parameters:
      - snapshot_name: $CIP/SAVE-PreStage5.tgz
      - snapshot_location: before_stage_5
=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
