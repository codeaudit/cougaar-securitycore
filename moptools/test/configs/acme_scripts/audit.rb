#Cougaar Action to invoke a Servlet that creates an access 
# record in the audit system
#
module Cougaar
        module Actions
         	class InvokeAuditTestServlet < Cougaar::Action
            	def initialize(run)
                	super(run)
                    @run = run
		        end
		        def perform
                    @run.society.each_agent(true) do |agent|
                         url = "http://#{ agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/testAuditServlet"
	    				 result = Cougaar::Communications::HTTP.get(url)
	    				 puts(result)
	  				end
             	end
             end
   
        end
end