=begin experiment

name: ASMT-PING-1
description: MOAS
script: BaselineTemplate.rb
parameters:
  - run_count: 1
  - society_file: $CIP/configs/ping/MiniPingSociety.rb
#  - layout_file: $CIP/operator/layouts/AS-1K-layout.xml
  - layout_file: $CIP/configs/ping/Secure-MiniPing-layout.xml
  - archive_dir: $CIP/Logs
  
  - rules:
    - $CIP/csmart/config/rules/isat
    - $CIP/csmart/config/rules/yp
#    - $CIP/csmart/config/rules/logistics
# ######################################################
# Security rules
    - $CIP/csmart/config/rules/security
    - $CIP/csmart/lib/security/rules
    - $CIP/csmart/config/rules/security/mop
    - $CIP/csmart/config/rules/security/testCollectData
   # ###
   # Redundant CA and persistence managers
#    - $CIP/csmart/config/rules/security/redundancy
#    - $CIP/csmart/config/rules/security/robustness
   # ###
# ######################################################
#    - $CIP/csmart/config/rules/security/robustness
#    - $CIP/csmart/config/rules/robustness
#    - $CIP/csmart/config/rules/robustness/uc1
  - community_rules:
    - $CIP/csmart/config/rules/security/communities
#    - $CIP/csmart/config/rules/robustness/communities

include_scripts:
#  - script: clearPnLogs.rb
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  - script: setup_ping.rb
  - script: $CIP/csmart/lib/security/scripts/setup_society_ping.rb
# ######################################################
# Security rules
  - script: $CIP/csmart/lib/security/scripts/build_config_jarfiles.rb
  - script: $CIP/csmart/lib/security/scripts/setup_acme_user.rb
  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
  - script: $CIP/csmart/lib/security/scripts/revoke_agent_and_node_cert.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc1.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc3.rb
#  - script: $CIP/csmart/lib/security/scripts/stress_security_uc4.rb
  - script: $CIP/csmart/lib/security/scripts/stress_security_uc5.rb
  - script: $CIP/csmart/lib/security/scripts/threatcon_level_change.rb
  - script: $CIP/csmart/lib/security/scripts/invalid_community_request.rb
  - script: $CIP/csmart/lib/security/scripts/check_mop.rb
  - script: $CIP/csmart/lib/security/scripts/parseResults.rb
  - script: $CIP/csmart/lib/security/scripts/saveAcmeEvents.rb
# ######################################################
#  - script: setup_robustness.rb
#  - script: network_shaping.rb
#  - script: cnccalc_include.rb
#  - script: standard_kill.rb

=end

CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist')

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
