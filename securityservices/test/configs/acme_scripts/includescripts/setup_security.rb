=begin script

include_path: setup_security.rb
description: special initialization for security

=end

CIP = ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'assessment', 'lib')
$:.unshift File.join(CIP, 'csmart', 'assessment', 'scripts')

require 'framework/scripting'
require 'cougaar/scripting'
require 'framework/configFiles'

insert_before :setup_run do
  do_action "BuildConfigJarFiles"
end

insert_after :society_running do
  do_action "PublishConditionalPolicies"
end
