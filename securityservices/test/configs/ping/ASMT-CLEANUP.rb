=begin experiment

name: ASMT-PING-CLEANUP-1
description: MOAS
script: $CIP/configs/ping/CleanupTemplate.rb
parameters:
  - run_count: 1
  - society_file: $CIP/configs/ping/MiniPingSociety.rb
#  - layout_file: $CIP/operator/layouts/AS-1K-layout.xml
  - layout_file: $CIP/configs/ping/Secure-MiniPing-layout.xml
  - archive_dir: $CIP/Logs
  
  - rules:
    - $CIP/csmart/config/rules/isat
  - community_rules:
    - $CIP/csmart/config/rules/security/communities

include_scripts:
=end

CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist')
# Below is the path when using open-source ACME
$:.unshift File.join(CIP, 'acme', 'acme_scripting',  'src', 'lib')
$:.unshift File.join(CIP, 'acme', 'acme_service', 'src', 'redist')

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
