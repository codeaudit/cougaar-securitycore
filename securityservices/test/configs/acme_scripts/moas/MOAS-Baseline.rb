=begin experiment

name: The-MOAS
group: Stress
description: baseline integrated ur restore run 
script: $CIP/csmart/scripts/definitions/RestoreTemplate.rb
parameters:
  - run_count: 1
  - snapshot_name: $CIP/SAVE-ASMT-PreStage4.tgz
  - archive_dir: /mnt/archive
  - stages:
    - 4
  
include_scripts:
  - script: $CIP/csmart/lib/isat/clearLogs.rb
  - script: $CIP/csmart/lib/isat/sms_notify.rb
  - script: $CIP/csmart/assessment/assess/setup_scripting.rb
  - script: $CIP/csmart/assessment/assess/asmt_init_network.rb
  - script: $CIP/csmart/lib/isat/initialize_network.rb
  - script: $CIP/csmart/lib/isat/network_shaping.rb
#  - script: $CIP/csmart/lib/isat/klink_reporting.rb
  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
  - script: $CIP/csmart/assessment/assess/inbound_aggagent_parallel_include.rb
  - script: $CIP/csmart/assessment/assess/outofbound_aggagent_include.rb
  - script: $CIP/csmart/lib/coordinator/leash_on_restart.rb
  - script: $CIP/csmart/lib/robustness/mic/freeze.rb

# ############################################################
# Security scripts
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  - script: $CIP/csmart/lib/security/scripts/build_config_jarfiles.rb
  - script: $CIP/csmart/lib/security/scripts/build_policies.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
  - script: $CIP/csmart/lib/security/scripts/security_archives.rb
  - script: $CIP/csmart/lib/security/scripts/saveAcmeEvents.rb
  - script: $CIP/csmart/lib/security/scripts/log_node_process_info.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_society_1000_ua.rb
  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
  - script: $CIP/csmart/lib/security/scripts/check_report_chain_ready.rb
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb

  # Advance to Oct 14
  - script: $CIP/csmart/lib/isat/advanceTime.rb
    parameters:
      - advance_location: after_stage
      - days: 1

  # Complete the security handoff
  - script: $CIP/csmart/lib/security/scripts/completehandoff.rb
    parameters:
      - start_label: after_stage
      - nodename: AVN-CO-NODE
      - enclave: 1-UA

  # Do the IP address change
  - script: $CIP/csmart/lib/isat/migrate.rb
    parameters:
      - migrate_location: after_stage
      - node_name: AVN-CO-NODE
      - target_network: 1-UA

  - script: $CIP/csmart/lib/robustness/mic/community_reassignment.rb
    parameters:
      - location: after_stage
      - old_community: REAR-COMM
      - new_community: 1-UA-COMM

  # Start the security handoff on Oct 13th.
  - script: $CIP/csmart/lib/security/scripts/starthandoff.rb
    parameters:
      - start_label: after_stage
      - nodename: AVN-CO-NODE

  # Advance time to Oct 13th
  - script: $CIP/csmart/lib/isat/advanceTime.rb
    parameters:
      - advance_location: after_stage
      - days: 3


=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
