
=begin script

include_path: setup_security.rb
description: special initialization for security

=end

CIP = ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib', 'security')

require 'lib/scripting'

insert_before :setup_run do
  do_action "SetAcmeUser"
end

