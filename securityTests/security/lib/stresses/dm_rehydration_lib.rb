require 'security/lib/policy_util'

class DomainManagerRehydrateReset < SecurityStressFramework
  @stressid = "DomainManagerRehydration"
  def initialize(run)
    super(run)
  end

  def getStressIds()
    return [@stressid]
  end


  def executeStress
    Thread.fork() do
      begin
        enclave = getAnEnclave()
        node    = getNonManagementNode(enclave)
        setPoliciesExperiment(enclave, node)
      rescue => ex
        saveAssertion(@stressid, "Exception occured = #{ex}, #{ex.backtrace.join("\n")}")
      end
    end
  end

  def setPoliciesExperiment(enclave, node)
#
#   Initialization of parameters
#
    failed = false
    policyNode, domainManager = getPolicyManagerNodeFromEnclave(enclave)
    saveAssertion(@stressid, "policy node = #{policyNode.name}")
    saveAssertion(@stressid, "other node = #{node.name}")
    # audit should happen as part of the bootstrap policy
#
# Does everything start as I expect?
#
    if !checkAudit(node)
      saveAssertion{@stressid, "No audit? - aborting test")
      saveResult(false, 'xyzzy', "Rehydration test aborted")
    end
#
# Kill the node, distribute policies, kill policy node, restart node
#
    saveAssertion(@stressid, "killing #{node.name}")
    run['node_controller'].stop_node(node)
    saveAssertion(@stressid,  "sending relay and installing policies")
    deltaPolicy(enclave, <<DONE)
      Delete RequireAudit
DONE
    persistUri = domainManager.uri+"/persistenceMetrics?submit=PersistNow"
    saveAssertion(@stressid, "uri = #{persistUri}")
    Cougaar::Communications::HTTP.get(persistUri)
    sleep(30)
# now audit is turned off and should not happen.      
    if checkAudit(policyNode)
      saveAssertion(@stressid,  "Audit?? commit policies failed - aborting")
      saveResult(false, 'xyzzy', "Rehydration policy aborted")
    end
    saveAssertion(@stressid,  "killing policy manager node (#{policyNode.name})")
    run['node_controller'].stop_node(policyNode)
    saveAssertion(@stressid,  "restarting node #{node.name}")
    run['node_controller'].restart_node(self, node)
    sleep(30)
    saveAssertion(@stressid,  "restarting domain manager node (#{policyNode.name})")
    run['node_controller'].restart_node(self, policyNode)
    sleep(30)
# audit should fail here also  - this is the real test
    if checkAudit(node)
      saveAssertion(@stressid,  "Rehydration test failed - audit should not occur")
      saveResult(false, 'xyzzy', "Rehydration policy test failed")
    else 
      saveAssertion(@stressid,  "Rehydration test succeeded")
      saveResult(true, 'xyzzy', "Rehydration test succeeded")
    end
    saveAssertion(@stressid,  "restoring audit policy")
    deltaPolicy(enclave, <<DONE)
      PolicyPrefix=%RestoredPolicy
      Policy RequireAudit = [
         AuditTemplate
         Require audit for all accesses to all servlets
      ]
DONE
  end

  def checkAudit(node)
    saveAssertion(@stressid,  "checking audit on node #{node.name}")
    url = "#{node.uri}/testAuditServlet"
    result = Cougaar::Communications::HTTP.get(url)
    return result.to_s =~ "TRUE"
  end

  def getPolicyManagerNodeFromEnclave(enclave)
    run.society.each_node do |node|
      node.each_facet(:role) do |facet|
        if facet[:role] == $facetManagement
          return [node,enclave + "PolicyDomainManager"]
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
    return run.society.nodes["MESSAGE-ATTACK-NODE"]
  end
end
