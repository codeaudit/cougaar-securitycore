=begin experiment

name: ART-AS-MOAS-1
description: MOAS
script: BaselineTemplate.rb
parameters:
  - run_count: 5
  - society_file: $CIP/csmart/config/societies/ua/full-tc20-232a703v.plugins.rb
  - layout_file: $CIP/operator/layouts/FULL-UA-MNGR-33H63N-layout.xml
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
    - $CIP/csmart/config/rules/security/testCollectData
# ############################################################
# Robustness rules
#    - $CIP/csmart/config/rules/security/robustness
#    - $CIP/csmart/config/rules/robustness
#    - $CIP/csmart/config/rules/robustness/uc1
# ############################################################
  - community_rules:
    - $CIP/csmart/config/rules/security/communities
#    - $CIP/csmart/config/rules/robustness/communities

include_scripts:
  - script: clearPnLogs.rb
# ############################################################
# Security scripts
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
#  - script: $CIP/csmart/lib/security/scripts/setup_society_1000_ua.rb
  - script: $CIP/csmart/lib/security/scripts/setup_userManagement.rb
#  - script: $CIP/csmart/lib/security/scripts/check_wp.rb
# ############################################################
#  - script: setup_robustness.rb
#  - script: network_shaping.rb
#  - script: cnccalc_include.rb
#  - script: standard_kill.rb

=end

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
