
=begin script

include_path: logNodeInfo.rb
description: log node process info

=end

require 'security/actions/logNodeInfo'

insert_before :wait_for_initialization do
  do_action "LogNodeInfo"
end

