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

    class KillAgents < Cougaar::Action
      def initialize(run, agents)
        super(run)
        @agents = agents
      end
      def perform
        nodes = {}
        @agents.each do |agent_name|
          agent = @run.society.agents[agent_name]
          if agent
            unless nodes.has_key?(agent.node.name)
              nodes[agent.node.name] = agent.node
            end
          end
        end
        @run.info_message "Killing Nodes #{nodes.keys.join(', ')}."
        nodes.each do |node_name, node_obj|
          @run.info_message "Killing node #{node_name}"
          @run['node_controller'].kill_node(self, node_obj)
        end
      end
    end

    class KillYPWPNodes < Cougaar::Action
      PRIOR_STATES = ["SocietyRunning"]
      def initialize(run)
        super(run)
      end
      def perform
        @run.info_message "Killing Nodes #{@run['nodes_to_kill'].join(', ')}"
        @run['nodes_to_kill'].each do |node|
          cougaar_node = @run.society.nodes[node]
          if cougaar_node
            @run['node_controller'].kill_node(self, cougaar_node)
          else
            @run.error_message "Cannot kill node #{node}, node unknown."
          end
        end
      end
    end

    class FindYPNodes < Cougaar::Action
      def initialize(run, *webs)
        super(run)
        @webs = webs
        @nodes = []
      end

      def perform
        if @webs == nil || @webs.empty?
          #puts "Finding yp servers for entire society"
          @run.society.each_agent do |agent|
            if agent.has_facet?(:subordinate_org_id)
              if agent.has_component?{|c| c.classname == "org.cougaar.yp.YPServer"}
                @nodes << agent.node.name
              end
            end
          end
        else
          #puts "Finding yp servers for webs #{@webs.join(', ')}"
          @run.society.each_host do |host|
            group = host.get_facet(:group).to_i
            if group != nil
              #puts "Host #{host.name} Group #{group}"
              if @webs.include?(group)
                host.each_node { |node|
                  node.each_agent{ |agent|
                    if agent.has_facet?(:subordinate_org_id)
                      if agent.has_component?{|c| c.classname == "org.cougaar.yp.YPServer"}
                        @nodes << agent.node.name
                      end
                    end
                  }
                }
              end
            else
              Cougaar.logger.error "Host #{host.name} does not have group facet"
            end
          end
        end
        @nodes.uniq!
        Cougaar.logger.info "YP NODES #{@nodes.join(',')} for Groups #{@webs.join(',')}"
        puts "YP NODES (#{@nodes.length}) #{@nodes.join(',')} for Groups #{@webs.join(',')}"
        @run['nodes_to_kill'] = @nodes
      end
    end

    class FindWPNodes < Cougaar::Action
      def initialize(run, *webs)
        super(run)
        @webs = webs
        @nodes = []
      end

      def perform
        if @webs == nil || @webs.empty?
          #puts "Finding wp servers for entire society"
          @run.society.each_node do |node|
            if node.has_facet?(:role)
              roles = node.get_facet(:role)
              if roles.include?("NameServer")
                @nodes << node.name
              end
            end
          end
        else
          #puts "Finding wp servers for webs #{@webs.join(', ')}"
          @run.society.each_host do |host|
            group = host.get_facet(:group).to_i
            if group != nil
              #puts "Host #{host.name} Group #{group}"
              if @webs.include?(group)
                host.each_node { |node|
                  if node.has_facet?(:role)
                    roles = node.get_facet(:role)
                    if roles.include?("NameServer")
                      @nodes << node.name
                    end
                  end
                }
              end
            else
              Cougaar.logger.error "Host #{host.name} does not have group facet"
            end
          end
        end
        @nodes.uniq!
        Cougaar.logger.info "WP NODES #{@nodes.join(',')} for Groups #{@webs.join(',')}"
        puts "WP NODES (#{@nodes.length}) #{@nodes.join(',')} for Groups #{@webs.join(',')}"
        @run['nodes_to_kill'] = @nodes
      end
    end

    class ApplyMEMStress < Cougaar::Action
      def initialize(run, mem_stress, *nodes)
        super(run)
        @mem_waster_class = 'org.cougaar.tools.csmart.plugins.mem.MemoryWasterPlugin'
        @mem_stress = mem_stress
        @nodes = nodes
      end

      def perform
        if @nodes == nil
          @nodes = []
          @run.society.each_node do |node|
            if node.agent.has_component?{|c| c.classname == @mem_waster_class}
              @nodes << node.name
            end
          end
          @nodes.uniq!
        end
        @nodes.each do |node_name|
            waste_mem = (JVM_MEMORY[node_name] * @mem_stress) / 100
            node = @run.society.nodes[node_name]
            result, uri = Cougaar::Communications::HTTP.get("#{node.agent.uri}/mem-waster?size=#{waste_mem}")
            Cougaar.logger.info "#{node.name}: Wasting memory #{waste_mem}"
            Cougaar.logger.info "#{result}" if result
        end
      end
    end

    class StressCPUOnNodes < Cougaar::Action
      PRIOR_STATES = ["SocietyLoaded"]
      DOCUMENTATION = Cougaar.document {
        @description = "Starts or stops the CPU stressor on one or more hosts of given nodes."
        @parameters = [
          {:percent=> "required, The percentage of CPU stress to apply."},
          {:nodes=> "optional, The comma-separated list of nodes whose hosts are to stress.  If omitted, all hosts are stressed."}
        ]
        @example = "do_action 'StressCPUOnNodes', 20, 'NCA-NODE,ROOT-CA-NODE'"
      }

      def initialize(run, percent, *nodes)
        super(run)
        @percent = percent
        nodes = nodes[0] if nodes[0].kind_of?(Array)
        @nodes = nodes
      end

      def perform
        hosts = []
        if @nodes == nil
          @run.society.each_service_host("acme") do |host|
            hosts << host.name
          end
          hosts.uniq!
        else
          @nodes.each do |node_name|
              node = @run.society.nodes[node_name]
              hosts << node.host.name
              hosts.uniq!
          end
          Cougaar.logger.info "Stressing CPU by #{@percent} % on hosts for nodes #{@nodes.join(',')}"
          Cougaar.logger.info "Stressing CPU by #{@percent} % on hosts #{hosts.join(',')}"
        end
        
        Cougaar.logger.error "Host list is empty in StressCPUOnNodes." if hosts.empty?
        cmd = "command[cpu]#{@percent}"
        hosts.each do |host|
          cougaar_host = run.society.hosts[host]
          @run.comms.new_message(cougaar_host).set_body(cmd).send if cougaar_host
        end
      end
    end
  end

  module States
    class NCAToBeUp < Cougaar::State
      DEFAULT_TIMEOUT = 30.minutes
      PRIOR_STATES = ["SocietyRunning"]
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end

      def process
       loop = true
        while loop
          sleep 1.minutes
          nca_agent = @run.society.agents['NCA']
          if nca_agent != nil
            result = Cougaar::Communications::HTTP.get("http://#{nca_agent.node.host.host_name}:#{@run.society.cougaar_port}/$NCA/list")
            if result && result.include?("glsinit")
              loop = false
            end
          end
        end
      end

      def unhandled_timeout
        @run.do_action "StopSociety"
        @run.do_action "StopCommunications"
      end
    end

    # Wait for this state to ensure given nodes can be killed
    class MyNodesPersistedFindProviders < Cougaar::State
      DEFAULT_TIMEOUT = 30.minutes
      PRIOR_STATES = ["SocietyRunning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for named Nodes to be ready to have persisted -- all agents must have persisted after FindProviders."
        @parameters = [
          {:nodes => "Nodes we want to wait for. If not given, use all in the society."}
        ]
        @example = "
          wait_for 'NodesPersistedFindProviders', 'FWD-A'
        "
      }
      
      def initialize(run)
	super(run)
	@nodes = nil
      end
      
      def process
        @nodes = @run['nodes_to_kill']
	@ready_nodes = []
	if @nodes == nil || @nodes.size == 0
	  @run.info_message("Will wait for all nodes in the society.")
	  @nodes = []
	  @run.society.each_node do |node|
	    @nodes << node
	  end
	end
	if @run['agent_p_watcher'] == nil
	  @run.info_message("Late install of agent persistence watcher!")
	  @run['agent_p_watcher'] = ::Ultralog::AgentPersistWatcher.new(run)
	end

	@run.info_message("Waiting for #{@nodes.size} nodes to persist after finding providers.")
	while (@ready_nodes.size < @nodes.size)
	  @nodes.each do |node|
	    if ! @ready_nodes.include?(node)
	      if @run['agent_p_watcher'].isNodeReady(node) 
		@ready_nodes << node
		if (node.kind_of?(String))
		  @run.info_message("Node #{node} has persisted after finding providers.")
		else
		  @run.info_message("Node #{node.name} has persisted after finding providers.")
		end
	      end # node was ready -- add it block
	    end # block to only look if not done
	  end # block to check all nodes

	  # If we're not currently done, block here waiting for
	  # the next event to come in. No point checking until it does.
	  if @ready_nodes.size < @nodes.size
	    event = @run.get_next_event
	  end
	end # end while loop waiting for all needed nodes
	# Done with the wait_for -- all needed nodes reported in
	@run.info_message("All needed nodes have persisted after finding providers.")
      end
      
      def unhandled_timeout
	@run.do_action "StopSociety" 
	@run.do_action "StopCommunications"
      end
    end
  end

end
