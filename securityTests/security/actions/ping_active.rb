
module Cougaar
   module States
     class PingActive < Cougaar::State
       DEFAULT_TIMEOUT = 40.minutes
       PRIOR_STATES = ["SocietyRunning"]
       DOCUMENTATION = Cougaar.document {
         @description = "Waits for agents to ping each other."
         @parameters = [
           {:timeout => "default = nil, Amount of time to wait in seconds."},
           {:block => "The timeout handler (unhandled: StopSociety, StopCommunications"}
         ]
         @example = "
           wait_for 'PingActive'
             or
           wait_for 'PingActive', 10.minutes
         "
       }

       def initialize(run, timeout=nil, &block)
         super(run, timeout, &block)
       end
       
       def process
	 @run['PingActive'] = false
	 @run.comms.monitor_cougaar_events
	 logInfoMsg "Waiting for ping active"
	 listener = @run.comms.on_cougaar_event { |event|
	   #logInfoMsg "Event: #{event.component} - #{event.data}"
	   if event.event_type=="STATUS" && event.component == "PingTimerPlugin"
	   #  logInfoMsg "Removing listener - Wait for ping active"
	     @run['PingActive'] = true
	     @run.comms.remove_on_cougaar_event(listener)
	   end
	 }
	 backup_sync = $stdout.sync
	 $stdout.sync = true
	 while (!@run['PingActive'])
           putc "."
	   sleep 30.seconds
	 end
	 $stdout.sync = backup_sync
	 #logInfoMsg "Done Wait for ping active"
       end # perform

       def unhandled_timeout
         @run.do_action "StopSociety"
         @run.do_action "StopCommunications"
       end
     end # PingActive
   end # module States
end # Cougaar
