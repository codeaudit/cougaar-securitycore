
#
# Perform any cleanup before starting the society
#
#

require 'security/lib/scripting'
require 'security/lib/stresses/jar_files.rb'

insert_before :transformed_society do
  do_action "InjectStress", "CleanupJarFiles", "cleanupJarFiles"
  do_action "GenericAction" do |run|
    `rm -f #{CIP}/workspace/test/*`
  end
end
