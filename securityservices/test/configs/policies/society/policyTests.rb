require 'cougaar/society_control'
require 'security/lib/message_util'

module Cougaar
  module Actions

    class WaitForUserManagerReady < Cougaar::Action
      def initialize(run)
        super(run)
      end

      def perform
        run.society.each_enclave do |enclave|
          ::Cougaar.logger.info "Waiting for user manager in #{enclave}"
          host, port, manager = getPolicyManager(enclave)
          waitForUserManager(manager)
        end
      end
    end


    class SaveAcmeEvents < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end

      def perform
        file = File.new("Events.log", "w+")
        @run.comms.on_cougaar_event do |event| 
          file.puts event 
        end
      end
    end 

    class InitDM < Cougaar::Action
      def perform
        run.society.each_enclave { |enclave|
          ::Cougaar.logger.info "Publishing conditional policy to #{enclave} policy domain manager"
          ensureBootPoliciesLoaded(enclave)
        }
      end
    end # InitDM

    class DomainManagerRehydrateReset < Cougaar::Action
      def initialize(run)
        @run = run
        super(run)
      end
    
      def perform
        begin
          enclave = getAnEnclave()
          node    = getNonManagementNode(enclave)
          setPoliciesExperiment(enclave, node)
        rescue => ex
          @run.info_message("Exception occured = #{ex}, #{ex.backtrace.join("\n")}")
        end
      end
    
      def setPoliciesExperiment(enclave, node)
    #
    #   Initialization of parameters
    #
        failed = false
        policyNode, domainManager = getPolicyManagerNodeFromEnclave(enclave)
        @run.info_message("policy node = #{policyNode.name}")
        @run.info_message("other node = #{node.name}")
        # audit should happen as part of the bootstrap policy
    #
    # Does everything start as I expect?
    #
        if !(checkAudit(node)) then
          @run.info_message("No audit? - aborting test")
        end
    #
    # Kill the node, distribute policies, kill policy node, restart node
    #
        @run.info_message("killing #{node.name}")
        run['node_controller'].stop_node(node)
        @run.info_message( "sending relay and installing policies")
        deltaPolicy(enclave, <<DONE)
          Delete RequireAudit
DONE
        persistUri = domainManager.uri+"/persistenceMetrics?submit=PersistNow"
        @run.info_message("uri = #{persistUri}")
        Cougaar::Communications::HTTP.get(persistUri)
        sleep(30)
    # now audit is turned off and should not happen.      
        if checkAudit(policyNode)
          @run.info_message( "Audit?? commit policies failed - aborting")
          @run.info_message("Rehydration policy aborted")
        end
        @run.info_message( "killing policy manager node (#{policyNode.name})")
        run['node_controller'].stop_node(policyNode)
        @run.info_message( "restarting node #{node.name}")
        run['node_controller'].restart_node(self, node)
        sleep(30)
        @run.info_message( "restarting domain manager node (#{policyNode.name})")
        run['node_controller'].restart_node(self, policyNode)
        sleep(30)
    # audit should fail here also  - this is the real test
        if checkAudit(node)
          @run.info_message("Rehydration test failed - audit should not occur")
        else 
          @run.info_message( "Rehydration test succeeded")
        end
        @run.info_message( "restoring audit policy")
        deltaPolicy(enclave, <<DONE)
          PolicyPrefix=%RestoredPolicy
          Policy RequireAudit = [
             AuditTemplate
             Require audit for all accesses to all servlets
          ]
DONE
      end
    
      def checkAudit(node)
        @run.info_message("checking audit on node #{node.name}")
        url = "#{node.uri}/testAuditServlet"
        result = Cougaar::Communications::HTTP.get(url)
        return (/TRUE/.match(result.to_s) != nil)
      end
    
      def getPolicyManagerNodeFromEnclave(enclave)
        run.society.each_node do |node|
          node.each_facet(:role) do |facet|
            if facet[:role] == $facetManagement
              node.each_agent do |agent|
                if /PolicyDomainManager/.match(agent.name) then
                  return [node, agent]
                end
              end
            end
          end
        end
      end
    
      def getAnEnclave()
        run.society.each_enclave do |enclave|
          return enclave
        end
      end
    
      def getNonManagementNode(enclave)
        return run.society.nodes["RearWorkerNode"]
      end
    end
    


  end
end
