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
require "socket"

module Assessment
  CPLUS5   =  6
  OPLAN1   = 20
  CPLUS7   =  1
  OPLAN2   = 11
  CPLUS10  = 29
  GLMSTIM  = 20
  
  # List of agents to be killed, EasyEasy set given by Mark Barger.
  EASYEASY_KILL_AGENTS = [ '1-35-ARBN', '1-6-INFBN',
                           '1-501-AVNBN', '127-DASB',
                           '191-ORDBN', '23-ORDCO',
                           '565-RPRPTCO', '71-MAINTBN' ]
  
  # List of agents to be killed from Robustness-UC1-Agentlist-2.txt
  EASY_KILL_AGENTS = [ '1-35-ARBN', '1-501-AVNBN',
                       '1-6-INFBN', '47-FSB', '592-ORDCO', '191-ORDBN',
                       '227-SUPPLYCO', '343-SUPPLYCO', '565-RPRPTCO',
                       '102-POL-SUPPLYCO', '110-POL-SUPPLYCO', '127-DASB' ]

  # List of agents to be killed from Robustness-UC1-Agentlist-1.txt
  INTERESTING_AGENT_LIST = [ 'TRANSCOM', '123-MSB', '1-35-ARBN', '1-501-AVNBN',
                             '1-6-INFBN', '47-FSB', '592-ORDCO', '191-ORDBN',
                             '227-SUPPLYCO', '343-SUPPLYCO', '565-RPRPTCO',
                             '102-POL-SUPPLYCO', '110-POL-SUPPLYCO', '127-DASB' ]
  
  # List of agents to be killed from Robustness-UC1-Agentlist-3.txt
  HARD_AGENT_LIST = [ 'TRANSCOM', '123-MSB', '1-35-ARBN', '1-501-AVNBN',
                      '1-6-INFBN', '47-FSB', '592-ORDCO', '191-ORDBN',
                      '227-SUPPLYCO', '343-SUPPLYCO', '565-RPRPTCO',
                      '102-POL-SUPPLYCO', '110-POL-SUPPLYCO', '127-DASB',
                      'NCA', 'OSC', 'PlanePacker', 'GlobalSea',
                      'TheaterGround', 'ShipPacker', '125-ORDBN' ]

  # List of agents whose arrival will be delayed by 10 days from
  # Robustness-UC1-Agentlist-4.txt
  ARRIVAL_DELAYED_AGENTS = [ '102-POL-SUPPLYCO', '110-POL-SUPPLYCO',
                         '191-ORDBN', '227-SUPPLYCO',
                         '343-SUPPLYCO', '565-RPRPTCO', '592-ORDCO' ]
  
  # List of agents whose optempo will be made HIGH
  # Robustness-UC1-Agentlist-6.txt
  OPTEMPO_HIGH_AGENTS = [ '2-BDE-1-AD', '1-35-ARBN', '1-6-INFBN', '2-6-INFBN',
                        '4-27-FABN', '40-ENGBN', '47-FSB' ]
  
  GLM_STIMULATED_AGENTS = {
    "1-35-ARBN"    => ["Robustness-UC1-Demand-Task-1.xml"],
    "1-501-AVNBN"  => ["Robustness-UC1-Demand-Task-2.xml", 
                       "Robustness-UC1-Demand-Task-3.xml", 
                       "Robustness-UC1-Demand-Task-4.xml"],
    "1-6-INFBN"    => ["Robustness-UC1-Demand-Task-5.xml", 
                       "Robustness-UC1-Demand-Task-6.xml", 
                       "Robustness-UC1-Demand-Task-7.xml"]
  }

  # The list of message rate thresholds as reported by the
  # AgentBusyPlugin events that must be crossed to determine that the
  # agent is busy. This is determined from other runs.
  AGENT_MSG_RATES = {
    '1-35-ARBN'        => 800.0,     # FWD-C
    '127-DASB'         => 6000.0,    # FWD-E
    '191-ORDBN'        => 8000.0,    # REAR-E
    '565-RPRPTCO'      => 10000.0    # REAR-G
  }
end

module Cougaar
  EnvSetup = 
  {
    # Jabber Server specifics
    'JabberServer'   => 'acmef',
    'JabberUser' =>  'acme_console',
    'JabberPassword' => 'c0ns0le',

    # Loading society variables
    'LoadSocietyFrom' => 'script',  # may be one of:  csmart, xml, script
    'SocietyScriptFilename' => '/mnt/bshared/socB/csmart/socB/SB-1AD-NEW-AL-RULES.xml.rb',

    'ConnectToOperatorService' => true,
    'OperatorServiceHost' => 'sv022',

    'CnCDbSetting' => {
                         'Server'   => nil,
                         'Port' => nil,
                         'Dbname'   => nil,
                         'User' =>  nil,
                         'Passwd' => nil
                      },

    'DataGrabberServer' => 'u173',

    'LogisticsTimeoutTime' => 9000,
    'PlanningBaselineTime' => 780
  }

  module Actions
    class SetEnvironmentGlobals < Cougaar::Action
      def initialize(run)
        super(run)
      end
      
      def perform
        @run['EnvSetup'] = Cougaar::EnvSetup;
        Cougaar::Communications::HTTP.set_auth('george', 'george')
      end
    end

    class OverrideSocietyParameters < Cougaar::Action
      PRIOR_STATES = ["SocietyLoaded"]
      def initialize(run, param_list)
        super(run)
        @params = param_list
      end
      
      def perform
        @params.each do |key, value| 
          @run.society.override_parameter(key, value)
        end
      end
    end

    class AddCnCParameters < Cougaar::Action
      PRIOR_STATES = ["SocietyLoaded"]
      def initialize(run)
        super(run)
      end

      def perform
        @run.society.each_node do |node|
          node.append_value_on_parameter("-Dorg.cougaar.config.path", "$COUGAAR_INSTALL_PATH/configs/CnCcalc")
          node.override_parameter("-Dorg.cougaar.core.logging.log4j.appender.CNCCALC.File", "$COUGAAR_INSTALL_PATH/workspace/log4jlogs/#{node.name}.cnclog")
          node.override_parameter("-Dcom.stdc.CnCcalc.database.url", "jdbc:postgresql://cnccalc-db/#{Socket.gethostname}")
          node.override_parameter("-Dcom.stdc.CnCcalc.database.mapping", "CnCcalcPostgresMapping.xml")
        end
      end
    end

    class AddMemoryWasterPlugin < Cougaar::Action
      PRIOR_STATES = ["SocietyLoaded"]
      def initialize(run, frequency=nil, deviation=nil)
        super(run)
        if frequency != nil
          @frequency = frequency
        else
          @frequency = "500000"
        end
        if deviation != nil
          @deviation = deviation
        else
          @deviation = "3600"
        end
      end
      
      def perform
        nodes = {}
        mem_waster_class = "org.cougaar.tools.csmart.plugins.mem.MemoryWasterPlugin"
        @run.society.each_agent do |agent|
          if (agent.get_facet(:superior_org_id) || agent.name == 'NCA')
            if !nodes.has_key?(agent.node.name)
              nodes[agent.node.name] = agent.node
            end
          end # if
        end # each_agent
        
        nodes.each_value do |node|
          node.add_component do |c|
            c.classname = mem_waster_class
            c.add_argument("/mem-waster")
            c.add_argument(@frequency)
            c.add_argument(@deviation)
          end
        end
      end
    end

    class CopyCommonConfigFile < Cougaar::Action
      PRIOR_STATES = ["SocietyLoaded"]
      def initialize(run, src_file, dest_file)
        super(run)
        @src_file_name = src_file
        @dest_file_name = dest_file
      end
      
      def perform
        cip = ENV['COUGAAR_INSTALL_PATH']
        if cip.nil? || cip==""
          puts "Unknown COUGAAR_INSTALL_PATH, Could not copy file #{@src_file_name}"
        else
          source_path = "#{cip}/csmart/assessment/configs/#{@src_file_name}"
          target_path = "#{cip}/configs/common/#{@dest_file_name}"
          puts "Source #{source_path}"
          puts "Target #{target_path}"
          if File.exist?("#{source_path}")
            File.delete(target_path) if File.exist?(target_path)
            File.link(source_path, target_path)
          else
            puts "File #{source_path} does not exist"
          end
        end
      end
    end

    class CopyFile < Cougaar::Action
      PRIOR_STATES = ["SocietyLoaded"]
      def initialize(run, src, dest)
        super(run)
        @source = src
        @destination = dest
      end
      
      def perform
        msg_body = "cp @source @destination"
        reply = @run.comms.new_message(@run.society.agents['NCA'].node.host).set_body("command[rexec] #{msg_body}").request(120)
        return reply.body
      end
    end

  end

end
