=begin script

include_path: setup_security.rb
description: special initialization for security

=end


require 'security/lib/persistence'

insert_after :setup_run do
  do_action "InsertPersistenceManagerReadyListener"
end

insert_after parameters[:persistence_mgr_watcher_label] do
  wait_for  "PersistenceManagerReadyWatcher", 60.minutes  
end
