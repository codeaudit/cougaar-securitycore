=begin script

include_path: setup_security.rb
description: special initialization for security

=end

CIP = ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib', 'security')

require 'lib/scripting'

insert_before :wait_for_initialization do
  wait_for  "UserManagerReady", "OSD.GOV", "/userManagerReady", 60.minutes
end

