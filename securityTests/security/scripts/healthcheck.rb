
require 'security/actions/healthCheck'

insert_after :setup_run do
  do_action "HealthCheck"
end

