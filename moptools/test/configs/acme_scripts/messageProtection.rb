#Actions to run The Malicious
# and Legitimate Message Servlets
#
#
module Cougaar
	module Actions
		 class SendLegitimateMessage < Cougaar::Action
              	def initialize(run)
              		super(run)
              		@run = run
              	end
              	def perform
              		begin
               			@run.society.each_agent(true) do |agent|
                					#Should only be one analyzer servlet, but we don't know which one
                					url ="http://#{agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/legitimateMessageServlet"
                					req=Cougaar::Communications::HTTP.get(url)
                				
                	end		
                	rescue
                		raise_failure "Could not do Legitimate Message Test"
                	end
                	
                end
          end 
          
          
           class SendMaliciousMessage < Cougaar::Action
              	def initialize(run)
              		super(run)
              		@run = run
              	end
              	def perform
              		begin
               			@run.society.each_agent(true) do |agent|
                					#Should only be one analyzer servlet, but we don't know which one
                					url ="http://#{agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/maliciousMessageServlet"
                					req=Cougaar::Communications::HTTP.get(url)
                				
                	end		
                	rescue
                		raise_failure "Could not do Malicious Message Test"
                	end
                	
                end
          end 
          
	
	end
end