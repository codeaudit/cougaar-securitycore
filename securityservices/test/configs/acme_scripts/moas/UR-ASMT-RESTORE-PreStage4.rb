=begin experiment

name: UR-ASMT-RESTORE-Baseline
description: UR-ASMT-RESTORE-Baseline
script: $CIP/csmart/scripts/definitions/UR-RestoreTemplate.rb
parameters:
  - run_count: 1
  - snapshot_name: $CIP/ASMT-SAVE-PreStage4.tgz
  - archive_dir: $CIP/Logs
  - stages:
    - 4
  
include_scripts:
  - script: $CIP/csmart/lib/isat/clearPnLogs.rb
  - script: $CIP/csmart/lib/isat/initialize_network.rb

# ############################################################
# Unit Re-assignment
  - script: $CIP/csmart/lib/robustness/objs/monitor_mobile_hosts.rb

  - script: $CIP/csmart/lib/isat/wait_for_ok.rb
    parameters:
      - wait_for_location: OCT_13

  - script: $CIP/csmart/lib/isat/wait_for_ok.rb
    parameters:
      - wait_for_location: OCT_17

  - script: $CIP/csmart/lib/isat/wait_for_ok.rb
    parameters:
      - wait_for_location: OCT_18

  - script: $CIP/csmart/lib/isat/wait_for_ok.rb
    parameters:
      - wait_for_location: OCT_19

  - script: $CIP/csmart/lib/isat/migrate.rb
    parameters:
      - migrate_location: OCT_13
      - node_name: AVN-CO-NODE
      - target_network: 1-UA

  - script: $CIP/csmart/lib/isat/migrate.rb
    parameters:
      - migrate_location: OCT_18
      - node_name: AVN-CO-NODE
      - target_network: CONUS-REAR

# ############################################################
# Security scripts
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
#  - script: $CIP/csmart/lib/security/scripts/build_config_jarfiles.rb
#  - script: $CIP/csmart/lib/security/scripts/build_policies.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
  - script: $CIP/csmart/lib/security/scripts/security_archives.rb
  - script: $CIP/csmart/lib/security/scripts/saveAcmeEvents.rb
  - script: $CIP/csmart/lib/security/scripts/log_node_process_info.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_society_1000_ua.rb
#  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
#  - script: $CIP/csmart/lib/security/scripts/revoke_agent_and_node_cert.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc1.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc3.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc4.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc5.rb
#  - script: $CIP/csmart/lib/security/scripts/threatcon_level_change.rb
#  - script: $CIP/csmart/lib/security/scripts/invalid_community_request.rb
#  - script: $CIP/csmart/lib/security/scripts/check_report_chain_ready.rb
#  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
#  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb
    parameters:
      - cleanup_label: snapshot_restored

# ############################################################
#  - script: setup_robustness.rb
#  - script: network_shaping.rb
#  - script: cnccalc_include.rb
#  - script: standard_kill.rb

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
