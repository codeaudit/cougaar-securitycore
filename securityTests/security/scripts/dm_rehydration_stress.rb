#
# Security ?: check that domain manager resets policy on its nodes on rehydrate
# When the domain manger rehydrates it is supposed to force a policy update
# for its subordinate node guards.
#

require 'security/lib/scripting'
require 'security/lib/stresses/dm_rehydration_lib'


insert_after :society_running do
  do_action "InjectStress", "DomainManagerRehydrateReset", "executeStress"
end
