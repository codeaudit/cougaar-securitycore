#TEST RUBY SCRIPT
module Cougaar
        module Actions
                #Requires Oplan ready
                class StartSecurityBlackboardTesting < Cougaar::Action
#                        PRIOR_STATES=["GLSReady"]

                        def initialize(run)
                                super(run)
                                @run = run

                        end
                        def perform
                                begin

                                        @run.society.each_agent(true) do |agent|
                                                url = "http://#{ agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/testManager?do=start&exp=#{@run.name}"

                                                result = Cougaar::Communications::HTTP.get(url)




                                        end

                                rescue
                                        raise_failure "Could not activate Testing", $!
                                end
                        end
                end
                #Require planning is complete
                class StopSecurityBlackboardTesting < Cougaar::Action
#                        PRIOR_STATES=["PlanningComplete"]
                        def initialize(run)
                                super(run)
                                @run = run
                        end
                        def perform
                                begin
                                        @run.society.each_agent(true) do |agent|
                                                url ="http://#{agent.node.host.host_name}:#{@run.society.cougaar_port}/#{agent.name}/testManager?do=end&exp=#{@run.name}"

                                                req=Cougaar::Communications::HTTP.get(url)
                                        end
                                rescue
                                        raise_failure "Could not stop testing"
                                end
                        end
                end
                
                class AnalyzeSecurityBlackboardResults < Cougaar::Action
                	def initialize(run)
                		super(run)
                		@run = run
                	end
                	def perform
                		begin
                			@run.society.each_agent(true) do |agent|
                					#Should only be one analyzer servlet, but we don't know which one
                					url ="http://#{agent.node.host.host_name}:#{@run.society.cougaar_port}/$#{agent.name}/analyze"
                					req=Cougaar::Communications::HTTP.get(url)
                				
                			end
                		rescue
                			raise_failure "Could not do analysis of results"
                		end
                	end
                end

        end
end
