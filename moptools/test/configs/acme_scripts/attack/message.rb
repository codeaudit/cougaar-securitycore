require "security/attack/attackutil"

class RequireSSL < SecurityStressFramework
#  def preConditionalGLSConnection
  def postConditionalNextOPlanStage
    success = "SUCCESS"
    if Util.agentExists('NO-SSL-ATTACK-NODE')
      success = "FAILURE"
    end
    file = Util.getTestResultFile
    file.print(success + "\tNon-SSL Communication\n")
    file.close()
  end # postConditionalNextOPlanStage

  def postTransformSociety
    # remove SSL from the node that shouldn't have it

    sslRMI      = "org.cougaar.core.mts.SSLRMILinkProtocol"
    rmiProtocol = "org.cougaar.core.mts.RMILinkProtocol"
    insertion   = "Node.AgentManager.Agent.MessageTransport.Component"
    
    getRun.society.each_node do |node|
      # don't use SSL for RMI communication
      node.each_facet("attacker") do |facet|
        if (facet["attacker"] == "NonSSL")
          node.remove_component(sslRMI)
          
          # make sure that either RMI exists instead
          node.add_component do |component|
            component.classname = rmiProtocol
            component.insertionpoint = insertion
          end
          break # out of the facet loop
        end
      end
    end
  end # postTransformSociety
end # RequireSSL

class Security3c1Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-3c1'
    @stresses = [ RequireSSL ]
  end
end
