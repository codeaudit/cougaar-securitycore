
=begin script

include_path: setup_security.rb
description: special initialization for security

=end

require 'security/lib/scripting'

insert_before :setup_run do
  do_action "SetAcmeUser"
end

