#TEST RUBY SCRIPT
module Cougaar
  module Actions
    class TestWPProtection < Cougaar::Action
      
      def initialize(run)
		super(run)
		@run = run
	
      end
      def perform
		begin
	  	  @run.society.each_agent(true) do |agent|
          	url = "http://#{ agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/wptest"
          	Cougaar::Communications::HTTP.get(url)
	    end
	  
	   rescue
	  	raise_failure "Could not activate Testing", $!
	   end
     end
    end
  end
end
