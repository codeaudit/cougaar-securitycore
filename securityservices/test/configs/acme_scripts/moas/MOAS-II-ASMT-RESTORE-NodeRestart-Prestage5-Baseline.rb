=begin experiment

name: MOAS-II-RESTORE-Basline
description: MOAS-II-preStage5-Restore-withNodeRestartStress-Baseline
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
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
    parameters:
      - user_mgr_label: society_running
  - script: $CIP/csmart/lib/security/scripts/log_node_process_info.rb
  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  - script: $CIP/csmart/lib/security/scripts/security_archives.rb
  # Do some basic security cleanup before the society is loaded.
  # This script should always be included whenever the society is loaded.
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb
    parameters:
      - cleanup_label: snapshot_restored
###########################################
#
# Node Kill and Restart scripts
#
  - script: $CIP/csmart/lib/isat/standard_restart_nodes.rb
    parameters:
      - start_tag: starting_stage
      - start_delay: 180
      - nodes_to_restart:
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
        - FSB-FUEL-WATER-SECTION-NODE
        - 123-MSB-HQ-NODE
        - 123-MSB-FOOD-NODE
        - 123-MSB-POL-NODE
        - 123-MSB-PARTS-NODE
        - 123-MSB-ORD-NODE

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
        - FSB-FUEL-WATER-SECTION-NODE
        - 123-MSB-HQ-NODE
        - 123-MSB-FOOD-NODE
        - 123-MSB-POL-NODE
        - 123-MSB-PARTS-NODE
        - 123-MSB-ORD-NODE

###########################################
  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
#  - script: $CIP/csmart/lib/isat/network_shaping.rb
#  - script: $CIP/csmart/lib/robustness/objs/deconfliction.rb
  - script: $CIP/csmart/assessment/assess/inbound_aggagent_include.rb
  - script: $CIP/csmart/assessment/assess/outofbound_aggagent_include.rb
  - script: $CIP/csmart/assessment/assess/cnccalc_include.rb
    parameters:
      - run_type: base
      - description: Stage 5 Baseline
  - script: $CIP/csmart/assessment/assess/analysis_baseline_cmds.rb
    parameters:
      - only_analyze: "moe1,moe3"
      - baseline_name: base2

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
