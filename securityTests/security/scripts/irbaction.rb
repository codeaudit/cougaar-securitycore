require 'security/lib/doIrb'

abort_on_exception = true

insert_before :setup_run do
  do_action "GenericAction" do |run|
    setRun(run)
    run.doIrb
  end
end
