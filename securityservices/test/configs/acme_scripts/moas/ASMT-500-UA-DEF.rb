=begin experiment

name: ART-AS-MOAS-1
description: MOAS
script: $CIP/csmart/scripts/definitions/BaselineTemplate.rb
parameters:
  - run_count: 1
#  - society_file: $CIP/csmart/config/societies/ua/full-tc20-232a703v.plugins.rb
  - society_file: $CIP/csmart/config/societies/ua/full-tc20-avn-162a208v.plugins.rb
#  - layout_file: $CIP/operator/layouts/FULL-UA-MNGR-33H63N-layout.xml
#  - layout_file: $CIP/operator/layouts/FULL-UA-MNGR-40H77N-layout.xml
  - layout_file: $CIP/operator/layouts/UR-557-layout-1.xml
#  - layout_file: $CIP/operator/layouts/AS-1K-layout.xml
#  - layout_file: $CIP/operator/layouts/AS-1K-robustness-layout.xml
  - archive_dir: $CIP/Logs
  
  - rules:
    - $CIP/csmart/config/rules/isat
    - $CIP/csmart/config/rules/yp
    - $CIP/csmart/config/rules/logistics
# ############################################################
# Security rules
    - $CIP/csmart/config/rules/security
    - $CIP/csmart/config/rules/security/testCollectData/MessageReaderAspect.rule
    - $CIP/csmart/config/rules/security/testCollectData/ServiceContractPlugin.rule

    - $CIP/csmart/config/rules/security/mts/loopback_protocol.rule
#    - $CIP/csmart/config/rules/security/mts/http_mts.rule
#    - $CIP/csmart/config/rules/security/mts/https_mts.rule
    - $CIP/csmart/config/rules/security/mts/sslRMI.rule
    - $CIP/csmart/config/rules/security/naming


#    - $CIP/csmart/config/rules/security/ruleset/base
#    - $CIP/csmart/config/rules/security/ruleset/crypto
#    - $CIP/csmart/config/rules/security/ruleset/jaas
#    - $CIP/csmart/config/rules/security/ruleset/accesscontrol
#    - $CIP/csmart/config/rules/security/ruleset/misc
#    - $CIP/csmart/config/rules/security/ruleset/monitoring
#    - $CIP/csmart/config/rules/security/ruleset/debug
#    - $CIP/csmart/config/rules/security/ruleset/signConfig

    - $CIP/csmart/lib/security/rules

#    - $CIP/csmart/config/rules/security/mop
#    - $CIP/csmart/config/rules/security/testCollectData
   # ###
   # Redundant CA and persistence managers
#    - $CIP/csmart/config/rules/security/redundancy
    - $CIP/csmart/config/rules/security/robustness
   # Run with only redundant PM
#    - $CIP/csmart/config/rules/security/redundancy/add_redundant_pm_facet.rule
#    - $CIP/csmart/config/rules/security/redundancy/adjust_memory.rule
#    - $CIP/csmart/config/rules/security/robustness/redundant_persistence_mgrs.rule

   # ###
# ############################################################
# Robustness rules
#    - $CIP/csmart/config/rules/robustness/manager.rule
#    - $CIP/csmart/config/rules/robustness/uc1/aruc1.rule
#    - $CIP/csmart/config/rules/robustness/uc1/debug/mic.rule
#    - $CIP/csmart/config/rules/robustness/uc1/tuning/collect_stats.rule
#    - $CIP/csmart/config/rules/robustness/uc9/deconfliction.rule
# ############################################################
  - community_rules:
    - $CIP/csmart/config/rules/security/communities
#    - $CIP/csmart/config/rules/robustness/communities

include_scripts:
  - script: $CIP/csmart/lib/isat/clearPnLogs.rb
  - script: $CIP/csmart/lib/isat/initialize_network.rb
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
#  - script: $CIP/csmart/lib/security/scripts/revoke_agent_and_node_cert.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc1.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc3.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc4.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc5.rb
#  - script: $CIP/csmart/lib/security/scripts/threatcon_level_change.rb
#  - script: $CIP/csmart/lib/security/scripts/invalid_community_request.rb
  - script: $CIP/csmart/lib/security/scripts/check_report_chain_ready.rb
#  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
#  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb

# ############################################################
#  - script: setup_robustness.rb
#  - script: network_shaping.rb
#  - script: cnccalc_include.rb
#  - script: standard_kill.rb

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
