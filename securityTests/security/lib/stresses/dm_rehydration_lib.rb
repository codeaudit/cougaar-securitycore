require 'security/lib/policy_util'

class DomainManagerRehydrateReset < SecurityStressFramework
  def initialize(run)
    super(run)
  end

  def getStressIds()
    return ["xyzzy"]
  end


  def executeStress
    enclave = getAnEnclave()
    node    = getNonManagementNode(enclave)
    setPoliciesExperiment(enclave, node)
  end

  def setPoliciesExperiment(enclave, node)
    failed = false
    policyNode = getPolicyManagerNodeFromEnclave(enclave)
    run.info_message "policy node = #{policyNode.name}"
    run.info_message "other node = #{node.name}"
    # audit should happen as part of the bootstrap policy
    if !checkAudit(node)
      run.info_message "No audit? - aborting test"
      saveResult(false, 'xyzzy', "Rehydration test aborted")
    end
    run.info_message "killing #{node.name}"
    run['node_controller'].stop_node(node)
    run.info_message "sending relay and installing policies"
    deltaPolicy(enclave, <<DONE)
      Delete RequireAudit
DONE
    sleep(30)
# now audit is turned off and should not happen.      
    if checkAudit(policyNode)
      run.info_message "Audit?? commit policies failed - aborting"
      saveResult(false, 'xyzzy', "Rehydration policy aborted")
    end
    run.info_message "sleeping for persistence..."
    sleep(7*60)
    run.info_message "killing policy manager node (#{policyNode.name})"
    run['node_controller'].stop_node(policyNode)
    run.info_message "restarting node #{node.name}"
    run['node_controller'].restart_node(self, node)
    sleep(30)
    run.info_message "restarting domain manager node (#{policyNode.name})"
    run['node_controller'].restart_node(self, policyNode)
    sleep(30)
# audit should fail here also  - this is the real test
    if checkAudit(node)
      run.info_message "Rehydration test failed - audit should not occur"
      saveResult(false, 'xyzzy', "Rehydration policy test failed")
    else 
      run.info_message "Rehydration test succeeded"
      saveResult(true, 'xyzzy', "Rehydration test succeeded")
    end
    run.info_message "restoring audit policy"
    deltaPolicy(enclave, <<DONE)
      PolicyPrefix=%RestoredPolicy
      Policy RequireAudit = [
         AuditTemplate
         Require audit for all accesses to all servlets
      ]
DONE
  end

  def checkAudit(node)
    run.info_message "checking audit on node #{node.name}"
    url = "http://#{ node.host.host_name}:#{node.cougaar_port}/$#{node.name}/testAuditServlet"
    result = Cougaar::Communications::HTTP.get(url)
    return result.to_s =~ "TRUE"
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

  def getAnEnclave()
    run.society.each_enclave do |enclave|
      return enclave
    end
  end

  def getNonManagementNode(enclave)
    return run.society.nodes["MESSAGE-ATTACK-NODE"]
  end
end
