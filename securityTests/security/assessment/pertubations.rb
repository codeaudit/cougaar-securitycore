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

    class ArrivalDelayPertubation < Cougaar::Action
      PRIOR_STATES = ["SocietyRunning"]
      RESULTANT_STATE = 'SocietyPlanning'
      def initialize(run, agents, days)
        super(run)
        @agents = agents
        @delay = days
      end
      def perform
        plan = ::UltraLog::OPlan.from_society(@run.society)
        for agent in @agents
          org = plan[agent]
          org["Deployment"].save(nil, nil , @delay )
        end
        result = plan.publish
      end
    end

    class EmploymentDefensiveOptempoPertubation < Cougaar::Action
      PRIOR_STATES = ["SocietyRunning"]
      RESULTANT_STATE = 'SocietyPlanning'
      def initialize(run, agents, optempo)
        super(run)
        @agents = agents
        @optempo = optempo
      end
      def perform
        plan = ::UltraLog::OPlan.from_society(@run.society)
        for agent in @agents
          org = plan[agent]
          org["Employment-Defensive"].save(@optempo, nil , nil )
        end
        result = plan.publish
      end
    end

    class IncreaseDemandPertubation < Cougaar::Action
      PRIOR_STATES = ["SocietyRunning"]
      RESULTANT_STATE = 'SocietyPlanning'
      def initialize(run, stimulation_list)
        super(run)
        @stimulation_list = stimulation_list
      end
      def perform
        @stimulation_list.each do |agent_name, file_list|
           puts "Agent : #{agent_name}"
           agent = @run.society.agents[agent_name]
           begin
             stimulator = ::UltraLog::GLMStimulator.for_cougaar_agent(agent)
           rescue
             puts "****Error in accessing GLM Stimulator servlet"
             Cougaar.logger.error "Error in accessing GLM Stimulator servlet"
             Cougaar.logger.error $!
             Cougaar.logger.error $!.backtrace.join("\n")
           end
           for fname in file_list
             puts "    file: #{fname}"
             stimulator.inputFileName = fname
             begin
               stimulator.update
             rescue
               puts "****Error in accessing GLM Stimulator servlet"
               Cougaar.logger.error "Error in accessing GLM Stimulator servlet"
               Cougaar.logger.error $!
               Cougaar.logger.error $!.backtrace.join("\n")
             end
           end
        end
      end
    end

  end

end
