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
    - $CIP/csmart/config/rules/security
#    - $CIP/csmart/config/rules/security/robustness
    - $CIP/csmart/config/rules/security/testCollectData
#    - $CIP/csmart/config/rules/robustness
#    - $CIP/csmart/config/rules/robustness/uc1
  - community_rules:
    - $CIP/csmart/config/rules/security/communities
#    - $CIP/csmart/config/rules/robustness/communities

include_scripts:
#  - script: clearPnLogs.rb
  - script: setup_ping.rb
  - script: setup_security.rb
#  - script: setup_robustness.rb
#  - script: network_shaping.rb
#  - script: cnccalc_include.rb
#  - script: standard_kill.rb

=end

CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
