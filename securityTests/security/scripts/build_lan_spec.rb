=begin script

include_path: setup_security.rb
description: specifies a lan for the test network configuration service

=end

require 'security/lib/scripting'
require 'security/actions/buildLanSpec.rb'

insert_before :setup_run do
  do_action "BuildLanSpec", parameters[:lan_nodes]
end
