puts ""

=begin experiment

# This experiment demonstrates how to build a society configuration file by using ACME experiments.

name: SECURITY_TUTORIAL
description: Tutorial for the security services.
script: $CIP/configs/security-tutorial/TransformTemplate.rb
parameters:
  - run_count: 1
  - society_file: $CIP/configs/security-tutorial/OneNodeSociety.rb
  - layout_file: $CIP/configs/security-tutorial/OneNodeLayout.xml
  
  - rules:
    - $CIP/csmart/config/rules/isat
    - $CIP/csmart/config/rules/yp
# ######################################################
# Security rules
    - $CIP/csmart/config/rules/security
    - $CIP/csmart/config/rules/security/mts/loopback_protocol.rule
    - $CIP/csmart/config/rules/security/mts/https_mts.rule
    - $CIP/csmart/config/rules/security/naming
    - $CIP/configs/security-tutorial/setupRootCaManager.rule
  - community_rules:
    - $CIP/csmart/config/rules/security/communities

include_scripts:
#  - script: setup_ping.rb
# ######################################################

=end

CIP = ENV['CIP']
$:.unshift File.join(CIP, 'csmart', 'acme_scripting', 'src', 'lib')
$:.unshift File.join(CIP, 'csmart', 'acme_service', 'src', 'redist')

require 'cougaar/scripting'
Cougaar::ExperimentDefinition.register(__FILE__)
