
include "setup_userManagement.rb"

insert_after :society_running do
  do_action "PublishConditionalPolicies"
end

