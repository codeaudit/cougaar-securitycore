#Cougaar Actions to Trigger injection of blackboard comprise agent onto the blackboard
#
module Cougaar
        module Actions
                class InjectBlackboardCompromise < Cougaar::Action
    	            def initialize(run, agentname)
                        super(run)
	                    @agentname =agentname
                    	@run = run
                	end
                	def perform
                        @run.society.each_agent do |agent|
                                if agent.name==@agentname
                                        url = "http://#{ agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/compromiseBlackboard"
                                                Cougaar::Communications::HTTP.get(url)
                                end
                        end
                 	end
               	 end

        end
end

