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

def irb(b)
  prompt = "ruby-> "
  while TRUE
    print prompt
    begin
      input = $stdin.gets()
      if input == nil || input == "quit\n" then
        break
      end
      puts eval(input, b)
    rescue Exception => exception
      puts("#{exception} #{exception.backtrace.join("\n")}")
    end
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


    class PolicyTestAction < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
        @web = SRIWeb.new()
      end

      def perform(name)
        agentName1 = "testBounceOne"
        agentName2 = "testBounceTwo"
        @agent1 = nil
        @agent2 = nil
        @run.society.each_agent do |agent|
          if (agent.name == agentName1) then
            @agent1 = agent
          end
          if (agent.name == agentName2) then
            @agent2 = agent
          end
        end
        @enclave = @agent1.host.enclave
        @run.info_message("***********************#{name}***********************")
        $policyTestCount += 1
      end

      def sendRelay(a,b)
        @web.getHtml("#{a.uri}/message/send?address=#{b.name}&Send=Submit")
      end

      def clearRelays(a)
        regexp=Regexp.compile"#{a.name}\/([0-9]+)[^0-9]"
        relays = @web.getHtml("#{a.uri}/message/list").body
        while m = regexp.match(relays) do
          #puts m
          #puts m[1]
          @web.getHtml("#{@a.uri}/message/delete?uid=#{a.name}/#{m[1]}")
          relays = @web.getHtml("#{a.uri}/message/list").body
        end
      end

      def checkRelays(a)
        result = @web.getHtml("#{a.uri}/message/list").body
        !(result.include?("no response"))
      end

      def sendVerb(a, b, verb)
        @web.postHtml("#{a.uri}/message/sendVerb/Sending", 
                      ["address=#{b.name}", "verb=#{verb}"])
      end

      def checkVerb(b, verb)
        result = @web.getHtml("#{b.uri}/message/receiveVerb").body
        result.include?("Task received with verb #{verb}")
      end

    end


########################################################################
#   Beginnining of test actions
########################################################################



#---------------------------------Test----------------------------------
    class DomainManagerRehydrateReset < PolicyTestAction
      def initialize(run)
        super(run)
      end
    
      def perform
        super("Domain Manager Rehydration")
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
        deltaPolicy(enclave, <<-DONE)
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
        @run.info_message("Waiting an additional #{waitTime} seconds for the rest")
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
        deltaPolicy(enclave, <<-DONE)
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
    class ServletTest01 < PolicyTestAction
      def initialize(run)
        super(run)
      end

      def test1(web)
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
        deltaPolicy(enclave, <<-DONE)
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
        deltaPolicy(enclave, <<-DONE)
          Policy RestoredSocietyAdminAuth  = [ 
            ServletAuthenticationTemplate
            All users must use Password, PasswordSSL, CertificateSSL
            authentication when accessing the servlet named SocietyAdminServlet
          ]
        DONE
        pw.wait(60)
      end

      def perform
        super("auth servlet test")
        begin 
          test1(@web)
        rescue => ex
          @run.info_message("Caught exception #{ex}, #{ex.backtrace.join("\n")}")
        end
      end
    end #ServletTest1
#---------------------------------End Test------------------------------


#---------------------------------Test----------------------------------

    class CommunicationTest01 < PolicyTestAction
      def initialize(run)
        super(run)
        @msgPingTimeout = 20.seconds
      end

      def checkSend
        clearRelays(@agent2)
        sendRelay(@agent1, @agent2)
        sleep(@msgPingTimeout)
        checkRelays(@agent1)
      end

      def perform
        super("auth policy test")
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
        deltaPolicy(@enclave, <<-DONE)
          Agent #{@agent1.name}
          Agent #{@agent2.name}

          Policy StopCommunication = [ 
            GenericTemplate
            Priority = 3,
            %urn:Agent##{@agent1.name} is not authorized to perform
            $Action.owl#EncryptedCommunicationAction  
            as long as
            the value of $Action.owl#hasDestination
            is a subset of the set { %urn:Agent##{@agent2.name} }
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
        deltaPolicy(@enclave, <<-DONE)
          Delete StopCommunication
        DONE

      end
    end # CommunicationTest01



#---------------------------------End Test------------------------------

#---------------------------------Test----------------------------------
    class CommunicationTest02 < PolicyTestAction
      def initialize(run)
        super(run)
        @verb1      = "Arm"
        @verb2      = "GetWater"
        @timeout    = 15
      end


      def perform()
        super("Verb Policy Test")
        @run.info_message("Sending message from #{@agent1.name} to " +
                          "#{@agent2.name} with verb #{@verb1}")
        sendVerb(@agent1, @agent2, @verb1)
        @run.info_message("Checking  if message was received...")
        sleep(@timeout)
        if (!checkVerb(@agent2, @verb1)) then
          @run.info_message("should be able to send message")
          @run.info_message("test failed")
          return
        end
        @run.info_message("    ... received")
        @run.info_message("Adding policy denying verb #{@verb2}")
        pw = PolicyWaiter.new(@run, @agent1.node.name)
        deltaPolicy(@enclave, <<-EndVerbPolicy)
          PolicyPrefix=%VerbTest

          Policy NoGetWater = [ 
            GenericTemplate
            Priority = 3,
            $Actor.owl#Agent is not authorized to perform
            $Action.owl#EncryptedCommunicationAction  
            as long as
            the value of $Ultralog/UltralogAction.owl#hasSubject
            is a subset of the set 
            { $Ultralog/Names/EntityInstances.owl##{@verb2} }
          ]
        EndVerbPolicy
        if (!pw.wait(120)) then
          @run.info_message("test failed")
          return
        end
        @run.info_message("Policy committed")
        @run.info_message("Sending message with verb #{@verb2}")
        sendVerb(@agent1, @agent2, @verb2)
        @run.info_message("Checking if message was received...")
        sleep(@timeout)
        if (checkVerb(@agent2, @verb2)) then
          @run.info_message("should not be able to send message")
          return
        end
        @run.info_message(" ...not received")
        @run.info_message("Test passed - restoring policies")
        deltaPolicy(@enclave, <<-RestorePolicy)
          Delete NoGetWater
        RestorePolicy
        $policyPassedCount += 1
      end



    end

#---------------------------------End Test------------------------------

#---------------------------------Test----------------------------------

    class CommunicationTest03 < PolicyTestAction
      def initialize(run)
        super(run)
        @enclave = "Rear"
        @agent1.name = "testBounceOne"
        @agent2.name = "testBounceTwo"
        @msgPingTimeout = 20.seconds
      end

      def sendUri(a,  b)
        "#{a.uri}/message/send?address=#{b.name}&Send=Submit"
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


      def checkUri(a)
        "#{a.uri}/message/list"
      end

      def deleteUri(a)
        "#{a.uri}/message/delete?uid="
      end

      def clearRelays(a)
        regexp=Regexp.compile"#{a.name}\/([0-9]+)[^0-9]"
        relays = @web.getHtml(checkUri(a)).body
        while m = regexp.match(relays) do
          #puts m
          #puts m[1]
          @web.getHtml("#{deleteUri(a)}#{a.name}/#{m[1]}")
          relays = @web.getHtml(@checkUri).body
        end
      end

      def checkSend(a,b)
        clearRelays(b)
        @web.getHtml(sendUri(a,b))
        sleep(@msgPingTimeout)
        result = @web.getHtml(checkUri(b)).body
        !(result.include?("no response"))
      end

      def perform
        newTest(@run, "half enforcement test")
        @agent1 = @run.society.agents[@agent1.name]
        @agent2 = @run.society.agents[@agent2.name]
        @run.info_message("Attempting to send message")
        if (checkSend(@agent1, @agent2)) then
          @run.info_message("Message sent and ack received")
        else
          @run.info_message("Should be able to talk - test failed")
          return
        end
        pw = PolicyWaiter.new(@run, @agent1.node.name)
        @run.info_message("Inserting policy preventing  communication")
        deltaPolicy(@enclave, <<-DONE)
          Agent #{@agent1.name}
          Agent #{@agent2.name}

          Policy StopCommunicationOne = [ 
            GenericTemplate
            Priority = 3,
            %urn:Agent##{@agent1.name} is not authorized to perform
            $Action.owl#EncryptedCommunicationAction  
            as long as
            the value of $Action.owl#hasDestination
            is a subset of the set { %urn:Agent##{@agent2.name} }
          ]

          Policy StopCommunicationTwo = [ 
            GenericTemplate
            Priority = 3,
            %urn:Agent##{@agent2.name} is not authorized to perform
            $Action.owl#EncryptedCommunicationAction  
            as long as
            the value of $Action.owl#hasDestination
            is a subset of the set { %urn:Agent##{@agent1.name} }
          ]
        DONE
        if (!pw.wait(200)) then
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
        deltaPolicy(@enclave, <<-DONE)
          Delete StopCommunicationOne
          Delete StopCommunicationTwo
        DONE

      end
    end # CommunicationTest03



#---------------------------------End Test------------------------------



#---------------------------------Test----------------------------------
    class BlackboardTest < PolicyTestAction
      def initialize(run)
        super(run)
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
        super("Blackboard OrgActivity Test")
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
        deltaPolicy(enclave, <<-DONE)
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
        deltaPolicy(enclave, <<-DONE)
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
