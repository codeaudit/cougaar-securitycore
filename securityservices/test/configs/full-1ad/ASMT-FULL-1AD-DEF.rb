=begin experiment

name: ART-AS-MOAS-1
description: MOAS
script: $CIP/csmart/scripts/definitions/BaselineTemplate.rb
parameters:
  - run_count: 1
#  - society_file: $CIP/csmart/config/societies/ua/full-tc20-232a703v.plugins.rb
  - society_file: $CIP/csmart/config/societies/ad/FULL-1AD-TC20.rb
#  - layout_file: $CIP/operator/layouts/FULL-UA-TC20-35H41N-layout.xml
#  - layout_file: $CIP/operator/layouts/FULL-1AD-ASMT-layout.xml
  - layout_file: $CIP/operator/layouts/FULL-1AD-ASMT-T20-layout.xml
  - archive_dir: $CIP/Logs
  
  - rules:
    - $CIP/csmart/config/rules/isat
    - $CIP/csmart/config/rules/yp
    - $CIP/csmart/config/rules/logistics
# ############################################################
# Security rules
    - $CIP/csmart/config/rules/security
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
#  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
# ############################################################
# Security scripts
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
# do not enable this for the test bed
##  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
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
#  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
#  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  - script: $CIP/csmart/lib/security/scripts/cleanup_society.rb

=end

CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist')

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
