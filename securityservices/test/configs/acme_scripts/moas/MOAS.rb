=begin experiment

name: The-MOAS
group: Stress
description: The-MOAS
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

###################

#  - script: $CIP/csmart/assessment/assess/cnccalc_include.rb
#    parameters:
#      - run_type: stress
#      - description: Stressed MOAS
#  - script: $CIP/csmart/assessment/assess/analysis_stress_cmds.rb
#    parameters:
#      - only_analyze: "moe1,moe2,moe3"
#      - baseline_name: S4SMB1V1

  - script: $CIP/csmart/lib/isat/standard_kill_nodes.rb
    parameters:
      - start_tag: starting_stage
      - start_delay: 60
      - nodes_to_kill:
        - AmmoTRANSCOM-NODE
        - 127-DASB-NODE
        - 501-FSB-NODE
        - 47-FSB-NODE
        - 125-FSB-NODE
        - 191-ORDBN-NODE
        - 1-CA-SEC-MGMT-NODE
        - 1-CA-ROB-MGMT-NODE
        - 2-CA-SEC-MGMT-NODE
        - 2-CA-ROB-MGMT-NODE
        - 3-CA-SEC-MGMT-NODE
        - 3-CA-ROB-MGMT-NODE
        - FSB-FUEL-WATER-SECTION-A-NODE
        - FSB-FUEL-WATER-SECTION-B-NODE
        - 123-MSB-HQ-NODE
        - 123-MSB-FOOD-NODE
        - 123-MSB-POL-NODE
        - 123-MSB-PARTS-NODE
        - 123-MSB-ORD-NODE

  - script: $CIP/csmart/assessment/assess/standard_mem_stress.rb
    parameters:
      - start_tag: starting_stage
      - start_delay: 0
      - end_tag: ending_stage
      - duration: 300
      - mem_stress: 25
      - nodes_to_stress:
        - AmmoTRANSCOM-NODE
        - 127-DASB-NODE
        - 501-FSB-NODE
        - 47-FSB-NODE
        - 125-FSB-NODE
        - 191-ORDBN-NODE
        - 1-CA-SEC-MGMT-NODE
        - 1-CA-ROB-MGMT-NODE
        - 2-CA-SEC-MGMT-NODE
        - 2-CA-ROB-MGMT-NODE
        - 3-CA-SEC-MGMT-NODE
        - 3-CA-ROB-MGMT-NODE
        - FSB-FUEL-WATER-SECTION-A-NODE
        - FSB-FUEL-WATER-SECTION-B-NODE
        - 123-MSB-HQ-NODE
        - 123-MSB-FOOD-NODE
        - 123-MSB-POL-NODE
        - 123-MSB-PARTS-NODE
        - 123-MSB-ORD-NODE

  - script: $CIP/csmart/assessment/assess/standard_cpu_stress.rb
    parameters:
      - start_tag: starting_stage
      - start_delay: 0
      - end_tag: ending_stage
      - duration: 300
      - cpu_stress: 25
      - nodes_to_stress:
        - AmmoTRANSCOM-NODE
        - 127-DASB-NODE
        - 501-FSB-NODE
        - 47-FSB-NODE
        - 125-FSB-NODE
        - 191-ORDBN-NODE
        - 1-CA-SEC-MGMT-NODE
        - 1-CA-ROB-MGMT-NODE
        - 2-CA-SEC-MGMT-NODE
        - 2-CA-ROB-MGMT-NODE
        - 3-CA-SEC-MGMT-NODE
        - 3-CA-ROB-MGMT-NODE
        - FSB-FUEL-WATER-SECTION-A-NODE
        - FSB-FUEL-WATER-SECTION-B-NODE
        - 123-MSB-HQ-NODE
        - 123-MSB-FOOD-NODE
        - 123-MSB-POL-NODE
        - 123-MSB-PARTS-NODE
        - 123-MSB-ORD-NODE

  - script: $CIP/csmart/lib/isat/standard_shape_K_links.rb
    parameters:
      - start_tag: society_ready
      - start_delay: 10
      - end_tag: ending_stage
      - duration: 330
      - bandwidth: 
      - ks_to_stress:
#        -  
#          router: CONUS-REAR-router
#          target: DIV
#          bandwidth: 3048kbit
#        -  
#          router: DIV-router
#          target: CONUS-REAR
#          bandwidth: 3048kbit
#        - 
#          router: CONUS-REAR-router
#          target: DIV-SUP
#          bandwidth: 3048kbit
#        - 
#          router: DIV-SUP-router
#          target: CONUS-REAR
#          bandwidth: 3048kbit
#        - 
#          router: CONUS-REAR-router
#          target: 1-UA
#          bandwidth: 3048kbit
#        - 
#          router: DIV-SUP-router
#          target: DIV
#          bandwidth: 3048kbit
#        - 
#          router: DIV-router
#          target: DIV-SUP
#          bandwidth: 3048kbit
#        - 
#          router: DIV-router
#          target: AVN-BDE
#          bandwidth: 3048kbit
#        - 
#          router: AVN-BDE-router
#          target: DIV
#          bandwidth: 3048kbit
        - 
          router: DIV-router
          target: 1-BDE
          bandwidth: 768kbit
        - 
          router: 1-BDE-router
          target: DIV
          bandwidth: 768kbit
#        - 
#          router: DIV-router
#          target: 2-BDE
#          bandwidth: 3048kbit
#        - 
#          router: 2-BDE-router
#          target: DIV
#          bandwidth: 3048kbit
#        - 
#          router: DIV-router
#          target: 3-BDE
#          bandwidth: 3048kbit
#        - 
#          router: 3-BDE-router
#          target: DIV
#          bandwidth: 3048kbit
#        - 
#          router: UA-router
#          target: 1-CA
#          bandwidth: 3048kbit
#        - 
#          router: 1-CA-router
#          target: 1-UA
#          bandwidth: 3048kbit
#        - 
#          router: UA-router
#          target: 2-CA
#          bandwidth: 3048kbit
#        - 
#          router: 2-CA-router
#          target: 1-UA
#          bandwidth: 3048kbit 
        - 
          router: UA-router
          target: 3-CA
          bandwidth: 768kbit
        - 
          router: 3-CA-router
          target: 1-UA
          bandwidth: 768kbit

  - script: $CIP/csmart/assessment/assess/cut_network_stressor.rb
    parameters:
      - handle: CUT-K8
      - start_tag: starting_stage
      - start_delay: 60
      - end_tag: end_of_run
      - duration: 120
      - ks_to_stress:
         - K8

  - script: $CIP/csmart/assessment/assess/cut_network_stressor.rb
    parameters:
      - handle: CUT-K5
      - start_tag: starting_stage
      - start_delay: 60
      - end_tag: end_of_run
      - ks_to_stress:
         - K5

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
