=begin experiment

name: Baseline
description: Baseline
script: $CIP/csmart/scripts/definitions/BaselineTemplate.rb
parameters:
  - run_count: 1
#  - society_file: $CIP/csmart/config/societies/ua/full-tc20-232a703v.plugins.rb
  - society_file: $CIP/csmart/config/societies/ad/FULL-1AD-TC20.rb
#  - layout_file: $CIP/operator/layouts/FULL-UA-TC20-35H41N-layout.xml
#  - layout_file: $CIP/operator/layouts/FULL-1AD-ASMT-layout.xml
  - layout_file: $CIP/operator/layouts/FULL-1AD-TC20-layout.xml
  - archive_dir: $CIP/Logs
  
  - rules:
    - $CIP/csmart/config/rules/isat
    - $CIP/csmart/config/rules/yp
    - $CIP/csmart/config/rules/logistics

include_scripts:
  - script: $CIP/csmart/lib/isat/clearPnLogs.rb
#  - script: $CIP/csmart/lib/isat/datagrabber_include.rb
  - script: $CIP/csmart/lib/security/scripts/setup_scripting.rb
  - script: $CIP/csmart/lib/security/scripts/security_archives.rb
  - script: $CIP/csmart/lib/security/scripts/saveAcmeEvents.rb

=end

CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist')

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
