
=begin script

include_path: enableCommunityXMLJar.rb
description: noop if community.xml.jar file exists, otherwise
             copy community.xml.jar.orig to community.xml.jar
             
=end

require 'security/actions/enableCommunityXMLJar'

insert_after :setup_run do
  do_action "EnableCommunityXMLJar"
end

