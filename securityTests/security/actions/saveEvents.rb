module Cougaar
  module Actions

   class SaveAcmeEvents < Cougaar::Action
     def initialize(run)
       super(run)
       @filename="#{CIP}/workspace/test/acme_events.log"
     end

     def perform()
       @run.comms.on_cougaar_event do |event|
	 eventCall(event)
       end
     end

     def eventCall(event)
       aFile = File.new(@filename, "aw")
       aFile << "#{Time.new} #{event.to_s}"
       aFile.close
     end
   end
  end
end
