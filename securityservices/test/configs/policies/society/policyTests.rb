require 'cougaar/society_control'
require 'security/lib/message_util'
require 'security/lib/web'


$policyTestCount   = 0
$policyPassedCount = 0


def getAnEnclave()
  run.society.each_enclave do |enclave|
    return enclave
  end
end

def newTest(run, name)
  run.info_message("***********************#{name}***********************")
  $policyTestCount += 1
end


module Cougaar
  module Actions

########################################################################
# Utility Classes
########################################################################

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
          loadBootPolicies(enclave)
        }
      end
    end # InitDM


########################################################################
#   Beginnining of test actions
########################################################################



#---------------------------------Test----------------------------------
    class DomainManagerRehydrateReset < Cougaar::Action
      def initialize(run)
        @run = run
        super(run)
      end
    
      def perform
        begin
          newTest(@run, "Domain Manager Rehydration")
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
        web = SRIWeb.new()
        failed = false
        policyNode, domainManager = getPolicyManagerNodeFromEnclave(enclave)
        @run.info_message("policy node = #{policyNode.name}")
        @run.info_message("other node = #{node.name}")
        # audit should happen as part of the bootstrap policy
    #
    # Does everything start as I expect?
    #
        if !(checkAudit(web, node)) then
          @run.info_message("No audit? - aborting test")
          return
        end
    #
    # Kill the node, distribute policies, kill policy node, restart node
    #
        @run.info_message("killing #{node.name}")
        @run['node_controller'].stop_node(node)
    # the sleep ensures that the node is really gone
        pw = PolicyWaiter.new(@run, policyNode.name)
        @run.info_message( "installing no audit policy")
        deltaPolicy(enclave, <<DONE)
          Delete RequireAudit
DONE
        persistUri = domainManager.uri+"/persistenceMetrics?submit=PersistNow"
        @run.info_message("uri = #{persistUri}")
        Cougaar::Communications::HTTP.get(persistUri)
    # now audit is turned off and should not happen.      
        if (!pw.wait(120) || checkAudit(web, policyNode)) then
          @run.info_message( "Audit?? commit policies failed - aborting")
          @run.info_message("Rehydration policy test aborted")
          return
        end
        @run.info_message( "killing policy manager node (#{policyNode.name})")
        @run['node_controller'].stop_node(policyNode)
    # the sleep ensures that the node is really gone
        @run.info_message( "restarting node #{node.name}")
        @run['node_controller'].restart_node(self, node)
        if !(checkAudit(web, node)) then
          @run.info_message("This means that you didn't wait long enough " +
                            "for #{node.name} to  die?")
          @run.info_message("Test failed")
          return
        end

   # now revive the domain manager
        pw = PolicyWaiter.new(@run, node.name)
        @run.info_message( "restarting domain manager node (#{policyNode.name})")
        @run['node_controller'].restart_node(self, policyNode)
    # audit should fail here also  - this is the real test
        if (!pw.wait(120) || checkAudit(web, node))
          @run.info_message("Rehydration test failed - audit should not occur")
          return
        else 
          $policyPassedCount += 1
          @run.info_message( "Rehydration test succeeded")
        end
        ps = PolicyWaiter.new(@run, node.name)
        @run.info_message( "restoring audit policy")
        pw = PolicyWaiter.new(@run, policyNode.name)
        deltaPolicy(enclave, <<DONE)
          PolicyPrefix=%RestoredPolicy
          Policy RequireAudit = [
             AuditTemplate
             Require audit for all accesses to all servlets
          ]
DONE
        pw.wait(240)
      end
    
      def checkAudit(web, node)
        @run.info_message("checking audit on node #{node.name}")
        done = false
        ret = false
        url = "#{node.uri}/testAuditServlet"
        while ! done do
          result = web.getHtml(url)
          #@run.info_message("result = #{result.body}")
          #@run.info_message("result = #{result.code}")
          # ignore transitory connection refused and forbidden codes
          done = (result.code == "200")
          if done then
            ret = (/TRUE/.match(result.body) != nil)
          else 
            sleep 15
          end
        end
        if ret then
          @run.info_message("Auditting enabled")
        else 
          @run.info_message("Auditting disabled")
        end
        ret
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
    
      def getNonManagementNode(enclave)
        return run.society.nodes["RearWorkerNode"]
      end
    end # DomainManagerRehydrateReset
#---------------------------------End Test------------------------------


#---------------------------------Test----------------------------------
    class ServletTest01 < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end

      def test1(web)
        newTest(@run, "auth servlet test")
        enclave = getAnEnclave()
        web.set_auth("mbarger", "badpassword")
        testAgent = nil
        @run.society.each_agent(true) do |agent|
          testAgent = agent
        end
        @run.info_message("Trying servlet requiring auth using bad password")
        @run.info_message("Agent = #{testAgent.name}")
        @run.info_message("uri = #{testAgent.uri}/move")
        result = 
          web.getHtml("#{testAgent.uri}/move", 60, 1, false)
        @run.info_message("return code = #{result.code}")
        if (result.code != "401") then
          @run.info_message("Test failed")
          return
        end
        pw = PolicyWaiter.new(@run, testAgent.node.name)
        @run.info_message("Removing society admin auth policy")
        deltaPolicy(enclave, <<DONE)
          Delete "SocietyAdminAuth"
DONE
        pw.wait(60)
        @run.info_message("Trying again")
        result = 
          web.getHtml("#{testAgent.uri}/move", 
                      60, 1, false)
        @run.info_message("return code = #{result.code}")
        if (result.code != "200") then
          @run.info_message("Test failed")
          return
        end
        $policyPassedCount += 1
        @run.info_message("test succeeded")
        pw = PolicyWaiter.new(@run, testAgent.node.name)
        @run.info_message("Restoring society admin auth policy")
        deltaPolicy(enclave, <<DONE)
          Policy RestoredSocietyAdminAuth  = [ 
            ServletAuthenticationTemplate
            All users must use Password, PasswordSSL, CertificateSSL
            authentication when accessing the servlet named SocietyAdminServlet
          ]
DONE
        pw.wait(60)
      end

      def perform
        begin 
          web = SRIWeb.new()
          test1(web)
        rescue => ex
          @run.info_message("Caught exception #{ex}, #{ex.backtrace.join("\n")}")
        end
      end
    end #ServletTest1
#---------------------------------End Test------------------------------


#---------------------------------Test----------------------------------

    class CommunicationTest01
      def initialize(run)
        super(run)
        @run = run
        @agentName1 = "testBounceOne"
        @agentName2 = "testBounceTwo"
        @web = SRIWeb.new()
      end

      def checkSend
        sendUri="#{@agent1.uri}/message/send?address=#{@agentName2}&Send=Submit"
        checkUri = "#{agent.uri}/message/list"
      end

      def perform
        @agent1 = @run.society.agents[agentName1]
      end
    end


#---------------------------------End Test------------------------------

#---------------------------------Test----------------------------------
    class BlackboardTest < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end

      def setbburi()
        testAgentName = "testBBPolicyAgent"
        @testAgent     = nil
        @run.society.each_agent do |agent|
          if agent.name == testAgentName then
            @testAgent = agent
            break
          end
        end
        @bburi = "#{@testAgent.uri}/OrgActivityAdd"
      end

      def checkBB(web)
        result = web.getHtml(@bburi)
        error = result.body.include?("java.lang.SecurityException: access denied")
        if (error) then
          @run.info_message("Failed to add OrgActivity object")
        else
          @run.info_message("Added OrgActivity object")
        end
        return !error
      end

      def perform
        newTest(@run, "Blackboard OrgActivity Test")
        setbburi()
        enclave = getAnEnclave()
        web = SRIWeb.new()
        if (!checkBB(web)) then
          @run.info_message("Initial policy does not allow add access to OrgActivity objects")
          @run.info_message("Test failed")
          return
        end
        pw = PolicyWaiter.new(@run, @testAgent.node.name)
        @run.info_message("Removing policy allowing Add access to OrgActivity objects")
        deltaPolicy(enclave, <<DONE)
          Delete OrgActivityAdd
DONE
        pw.wait(60)
        if (checkBB(web)) then
          @run.info_message("Add access to OrgActivity object still allowed")
          @run.info_message("Test failed")
          return
        end
        $policyPassedCount += 1
        @run.info_message("Test succeeded")
        pw = PolicyWaiter.new(@run, @testAgent.node.name)
        @run.info_message("Restoring policies")
        deltaPolicy(enclave, <<DONE)
          Policy OrgActivityAdd = [
            BlackboardTemplate
            A PlugIn in the role OrgActivityAdd can Add objects 
            of type OrgActivity
          ]
DONE
        pw.wait(60)
      end
    end # BlackboardTest
#---------------------------------End Test------------------------------

    class TestResults < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end

      def perform
        @run.info_message("#{$policyPassedCount} / #{$policyTestCount} tests passed")
      end
    end #Test Results


  end  # module Actions
end  # module Cougaar
