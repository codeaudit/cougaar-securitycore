=begin experiment

name: MOAS-II-AS-Save
description: MOAS-II-AS save pre-Stage5
script: $CIP/csmart/scripts/definitions/BaselineTemplate.rb
parameters:
  - run_count: 1
  - society_file: $CIP/csmart/config/societies/ua/full-tc20-232a703v.plugins.rb
#  - layout_file: $CIP/operator/layouts/FULL-UA-MNGR-33H63N-layout.xml
  - layout_file: $CIP/operator/layouts/FULL-UA-MNGR-40H77N-layout.xml
# for 2 rack
#  - layout_file: $CIP/operator/layouts/04-OP-layout.xml
  - archive_dir: $CIP/Logs
  
  - rules:
    - $CIP/csmart/config/rules/isat
#    - $CIP/csmart/config/rules/isat/uc3_nosec
    - $CIP/csmart/config/rules/yp
    - $CIP/csmart/config/rules/logistics
#    - $CIP/csmart/config/rules/assessment

# ############################################################
# Security rules
# Rules to enable the security framework.
    - $CIP/csmart/config/rules/security
# Rules to add components that apply security stresses
    - $CIP/csmart/lib/security/rules
# Rules that add components to compute the MOP values
# In particular, the rules add the blackboard access control components
    - $CIP/csmart/config/rules/security/mop
# Rule used to check that all agents are reporting for duty
    - $CIP/csmart/config/rules/security/testCollectData/ServiceContractPlugin.rule
# Rules to enable the redundant CA and redundant persistence manager
    - $CIP/csmart/config/rules/security/robustness
# Enable the rules below if the layout does not include the redundant CA and PM facets
#    - $CIP/csmart/config/rules/security/redundancy
# Enable the rules below to enable the redundant PMs but not the redundant CAs
#    - $CIP/csmart/config/rules/security/redundancy/add_redundant_pm_facet.rule
#    - $CIP/csmart/config/rules/security/redundancy/adjust_memory.rule
#    - $CIP/csmart/config/rules/security/robustness/redundant_persistence_mgrs.rule
# ############################################################
# Robustness rules
#    - $CIP/csmart/config/rules/robustness/manager.rule
#    - $CIP/csmart/config/rules/robustness/uc1
#    - $CIP/csmart/config/rules/robustness/uc9
#    - $CIP/csmart/config/rules/robustness/uc7
#    - $CIP/csmart/config/rules/robustness/UC3
#    - $CIP/csmart/config/rules/metrics/basic
#    - $CIP/csmart/config/rules/metrics/sensors
#    - $CIP/csmart/config/rules/metrics/serialization/metrics-only-serialization.rule
#    - $CIP/csmart/config/rules/metrics/rss/tic

#    - $CIP/csmart/config/rules/robustness/uc1/debug/mic.rule
#    - $CIP/csmart/config/rules/robustness/uc1/tuning/collect_stats.rule
# ############################################################
  - community_rules:
    - $CIP/csmart/config/rules/security/communities
#    - $CIP/csmart/config/rules/robustness/communities


include_scripts:
  - script: $CIP/csmart/lib/isat/clearPnLogs.rb
# ############################################################
# Security scripts
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  - script: $CIP/csmart/lib/security/scripts/setup_userManagementSAVE.rb
  - script: $CIP/csmart/lib/security/scripts/log_node_process_info.rb
  - script: $CIP/csmart/lib/security/scripts/check_message_queue.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_society_1000_ua.rb
  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
  - script: $CIP/csmart/lib/security/scripts/check_report_chain_ready.rb
  - script: $CIP/csmart/lib/security/scripts/revoke_agent_and_node_cert.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc1.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc3.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc4.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc5.rb
# scripts to be tested with UC1 only, involving killing nodes
#  - script: $CIP/csmart/lib/security/scripts/stress_security_robustness.rb
  - script: $CIP/csmart/lib/security/scripts/threatcon_level_change.rb
  - script: $CIP/csmart/lib/security/scripts/invalid_community_request.rb
  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  - script: $CIP/csmart/lib/security/scripts/saveAcmeEvents.rb
  - script: $CIP/csmart/lib/security/scripts/security_archives.rb
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb

# ############################################################
# Robustness include scripts
#  - script: $CIP/csmart/lib/robustness/objs/deconfliction.rb
#  - script: $CIP/csmart/lib/isat/network_shaping.rb
#  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
###########################################
# Assessment include scripts
#  - script: $CIP/csmart/assessment/assess/inbound_aggagent_include.rb
#  - script: $CIP/csmart/assessment/assess/outofbound_aggagent_include.rb
#  - script: $CIP/csmart/assessment/assess/cnccalc_include.rb

# ############################################################ 
  - script: $CIP/csmart/lib/isat/save_snapshot.rb
    parameters:
      - snapshot_name: $CIP/SAVE-PreStage5.tgz
      - snapshot_location: before_stage_5

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
