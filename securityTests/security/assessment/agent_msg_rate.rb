##
#  <copyright>
#  Copyright 2002 System/Technology Devlopment Corp.
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#

module Cougaar

  module Actions

    class AgentMsgRateKill < Cougaar::Action
      def initialize(run, agent_rate)
        super(run)
        @agent_rate = agent_rate
      end
      
      def perform
        event = @run.get_next_event
        @run.comms.on_cougaar_event do |event|
          if event.event_type=="STATUS" && event.component == "AgentMsgRatePlugin"
            re = /.* MSG_RATE=(\d*\.\d*)/
            msg_rate = re.match(event.data)[1].to_f
            unless @agent_rate.empty?
              if @agent_rate.has_key?(event.cluster_identifier)
                 threshold_rate = @agent_rate[event.cluster_identifier]
                 if msg_rate > threshold_rate
                    puts "Message rate #{msg_rate} exceeded threshold #{threshold_rate}" +
                         " for agent #{event.cluster_identifier}"
                    #sync_society
                    agent = @run.society.agents[event.cluster_identifier]
                    if agent
                      @run['node_controller'].kill_node(self, agent.node)
                    end
                    @agent_rate.delete(event.cluster_identifier)
                 end
              end
            end
          end
        end
      end
    end

  end

end
