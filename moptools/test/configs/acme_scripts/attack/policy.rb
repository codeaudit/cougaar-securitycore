require "security/attack/attackutil"

class NoAttackMessage < SecurityStressFramework
  def initialize
    super
  end

  def postConditionalNextOPlanStage
    Util.modifyPolicy Util.getEnclave('MessageAttacker'), <<DONE;

Policy NoMessageAttackerCommunication = [
  Priority = 2,
  $Actor.daml#Agent is not authorized to perform
   $Action.daml#EncryptedCommunicationAction as long as
   the value of $Action.daml#hasDestination
   is a subset of the set AttackerAgent
]
DONE
    Thread.fork {
#      print "Sleeping 5 minutes while the new policy distributes\n"
      sleep 5.minutes
      
      # now send a message to send to NCA
      agent = Util.getAgent("MessageAttacker")
      node = agent.node
      relayMessageTest(agent.name, node.name, "Policy denial", false)
    }
  end # postConditionalNextOplanStage
  
end # NoAttackMessage

class Security3a1Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-3a1'
    @stresses = [ NoAttackMessage ]
  end
end

