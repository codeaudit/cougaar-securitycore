#Cougaar Action to invoke a Servlet to test java policy  
#
module Cougaar
        module Actions
         	class TestJavaPolicy < Cougaar::Action
            	def initialize(run)
                	super(run)
                    @run = run
		        end
		        def perform
                    @run.society.each_agent(true) do |agent|
                         goodurl = "http://#{ agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/AuthorizedResourceServlet"
	    				 Cougaar::Communications::HTTP.get(goodurl)
	    				 badurl = "http://#{ agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/UnAuthorizedResourceServlet"
	    				 Cougaar::Communications::HTTP.get(badurl)
	  				end
             	end
             end
   
        end
end