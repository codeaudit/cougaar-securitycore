
=begin script

include_path: disableCommunityXMLJar.rb
description: removes the community.xml.jar file if it exists

=end

require 'security/actions/disableCommunityXMLJar'

insert_after :setup_run do
  do_action "DisableCommunityXMLJar"
end

