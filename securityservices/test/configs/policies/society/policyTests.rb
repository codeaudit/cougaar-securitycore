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
          bootPoliciesLoaded(enclave)
        }
      end
    end # InitDM


   class SetPoliciesTest < Cougaar::Action
      def initialize(run)
	 super(run)
      end

      def perform
        begin
          setPoliciesExperiment("Rear", "RearEnclaveCaNode")
        rescue
          run.info_message $!
          run.info_message $!.backtrace.join("\n")
        end
      end

      def setPoliciesExperiment(enclave, node)
        policyNode = getPolicyManagerNodeFromEnclave(enclave)
        otherNode  = run.society.nodes[node]
        run.info_message "policy node = #{policyNode.name}"
        run.info_message "other node = #{otherNode.name}"
        run.info_message "killing #{otherNode.name}"
        run['node_controller'].stop_node(otherNode)
        run.info_message "sending relay and installing policies"
        bootPoliciesLoaded(enclave)
        run.info_message "sleeping for persistence..."
        sleep(7*60)
        run.info_message "killing policy manager node (#{policyNode.name})"
        run['node_controller'].stop_node(policyNode)
        run.info_message "restarting node #{otherNode.name}"
        run['node_controller'].restart_node(self, otherNode)
        sleep(30)
        run.info_message "restarting domain manager node (#{policyNode.name})"
        run['node_controller'].restart_node(self, policyNode)
      end

      def getPolicyManagerNodeFromEnclave(enclave)
        run.society.each_node do |node|
          node.each_facet(:role) do |facet|
            if facet[:role] == $facetManagement
              return node
            end
          end
        end
      end
    end
  end
end
