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



def irb(b)
  prompt = "ruby-> "
  while TRUE
    print prompt
    output = nil
    begin
      input = $stdin.gets()
      if input == nil || input == "quit\n" then
        break
      end
      puts eval(input, b)
    rescue => exception
      puts("#{exception} #{exception.backtrace.join("\n")}")
    end
    puts output
  end
  puts "Continuing..."
end

module Cougaar
  module Actions

########################################################################
# Utility Classes
########################################################################

    class Irb < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end

      def perform
        @run.info_message("Primitive Ruby prompt - one line per command")
        @run.info_message("@run contains the run variable")
        @run.info_message("Type ^D or quit to exit")
        irb(binding)
      end
    end



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


########################################################################
#   Beginnining of test actions
########################################################################



#---------------------------------Test----------------------------------
    class DomainManagerRehydrateReset < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
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
    # Kill the node
    #
        @run.info_message("killing #{node.name}")
        @run['node_controller'].stop_node(node)

    #
    # Distribute policies, Persist, and Kill Policy Node
    #
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

    #
    # Restart node
    #
        @run.info_message( "restarting node #{node.name}")
        @run['node_controller'].restart_node(self, node)
        if !(checkAudit(web, node)) then
          @run.info_message("This means that you didn't wait long enough " +
                            "for #{node.name} to  die?")
          @run.info_message("Test failed")
          return
        end

    #
    # Check results
    #
        pw =  PolicyWaiter.new(@run, node.name)
   # now revive the domain manager
        @run.info_message( "restarting domain manager node (#{policyNode.name})")
        @run['node_controller'].restart_node(self, policyNode)
        @run.info_message"Waiting for first rehydrated policy on #{node.name}"
        if (!pw.wait(120)) then
          @run.info_message("Rehydrated policies did not commit to #{node.name}")
          @run.info_message("Audit test failed")
        end
        waitTime=90.seconds
        @run.info_message("First rehydrated policy received")
        @run.info_message("Waiting an additional #{waitTime} for the rest")
        sleep waitTime
    # audit should fail here also  - this is the real test
        if (checkAudit(web, node))
          @run.info_message("Rehydration test failed - audit should not occur")
          return
        else 
          $policyPassedCount += 1
          @run.info_message( "Rehydration test succeeded")
        end

     # 
     # Restore everything
     #
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
        run.society.each_agent do |agent|
          agent.each_facet(:role) do |facet|
            if facet[:role] == $facetPolicyManagerAgent then
               return [agent.node, agent]
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

    class CommunicationTest01 < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
        @enclave = "Rear"
        @agentName1 = "testBounceOne"
        @agentName2 = "testBounceTwo"
        @msgPingTimeout = 20.seconds
        @web = SRIWeb.new()
      end

      def initUris
        @sendUri = 
           "#{@agent1.uri}/message/send?address=#{@agentName2}&Send=Submit"
        @checkUri = "#{@agent1.uri}/message/list"
        @deleteUri = "#{@agent1.uri}/message/delete?uid="
      end

      def clearRelays
        regexp=Regexp.compile"#{@agentName1}\/([0-9]+)[^0-9]"
        relays = @web.getHtml(@checkUri).body
        while m = regexp.match(relays) do
          #puts m
          #puts m[1]
          @web.getHtml("#{@deleteUri}#{@agentName1}/#{m[1]}")
          relays = @web.getHtml(@checkUri).body
        end
      end

      def checkSend
        clearRelays
        @web.getHtml(@sendUri)
        sleep(@msgPingTimeout)
        result = @web.getHtml(@checkUri).body
        !(result.include?("no response"))
      end

      def perform
        newTest(@run, "Comm Test 01")
        @agent1 = @run.society.agents[@agentName1]
        @agent2 = @run.society.agents[@agentName2]
        initUris
        clearRelays
        @run.info_message("Attempting to send message")
        if (checkSend) then
          @run.info_message("Message sent and ack received")
        else
          @run.info_message("Should be able to talk - test failed")
          return
        end
        pw1 = PolicyWaiter.new(@run, @agent1.node.name)
        pw2 = PolicyWaiter.new(@run, @agent2.node.name)
        @run.info_message("Inserting policy preventing  communication")
        deltaPolicy(@enclave, <<DONE)
          Agent #{@agentName1}
          Agent #{@agentName2}

          Policy StopCommunication = [ 
            GenericTemplate
            Priority = 3,
            %urn:Agent##{@agentName1} is not authorized to perform
            $Action.owl#EncryptedCommunicationAction  
            as long as
            the value of $Action.owl#hasDestination
            is a subset of the set { %urn:Agent##{@agentName2} }
          ]
DONE
        if (!pw1.wait(200) || !pw2.wait(120)) then
          @run.info_message("no  policy received - test failed")
          return
        end
        @run.info_message("Attempting to send another message")
        if (checkSend) then
          @run.info_message("message should not have been received - test failed")
          return
        end
        $policyPassedCount += 1
        @run.info_message("Test succeeded - restoring policies")
        deltaPolicy(@enclave, <<DONE)
          Delete StopCommunication
DONE

      end
    end # CommunicationTest01



#---------------------------------End Test------------------------------

#---------------------------------Test----------------------------------
    class CommunicationTest02 < Cougaar::Action
      def initialize(run)
        @run = run
        @agentName1 = "testBounceOne"
        @agentName2 = "testBounceTwo"
        @web = SRIWeb.new()
      end

      def initSocietyVars
        @agent1 = nil
        @agent2 = nil
        @run.society.each_agent do |agent|
          if (agent.name == @agentName1) then
            @agent1 = agent
          end
          if (agent.name == @agentName2) then
            @agent2 = agent
          end
        end
        @sendUri = "#{@agent1.uri}/message/sendVerb/Sending"
      end


      def perform()
      end

      def sendMessage()
        #f = File.new("RearPolicyManagerNode.log", File::RDONLY)
        #p = f.pos
        #f.seek(0,IO::SEEK_END)
        #f.seek(p,IO::SEEK_SET)
        @web.postHtml(@sendUri, ["address=#{agent2.name}", "verb=GetWater"])
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

    class CheckRMISwitch < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
        @web = SRIWeb.new()
        @agentName1 = "testBounceOne"
        @agentName2 = "testBounceTwo"
      end

      def perform
        @agent1 = @run.society.agents[@agentName1]
        @agent2 = @run.society.agents[@agentName2]
        @sendUri = 
           "#{@agent1.uri}/message/send?address=#{@agentName2}&Send=Submit"
        pw = PolicyWaiter.new(@run, "testBounceOne")
        deltaPolicy(enclave, <<DONE)
          Delete EncryptCommunication
          Policy testEncryptCommunication = [
            MessageEncryptionTemplate
            Require SecretProtection on all messages from members of 
            $Actor.owl#Agent to members of $Actor.owl#Agent
          ]
DONE
        pw.wait(60)
        @web.getHtml(@sendUri)
      end
    end




  end  # module Actions
end  # module Cougaar
