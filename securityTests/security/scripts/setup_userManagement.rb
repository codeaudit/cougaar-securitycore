=begin script

include_path: setup_security.rb
description: special initialization for security

=end


require 'security/lib/scripting'

insert_before :wait_for_initialization do
  wait_for  "UserManagerReady", nil, "/userManagerReady", 60.minutes
end

