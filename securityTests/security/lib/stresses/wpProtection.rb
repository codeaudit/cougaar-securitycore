require 'security/lib/society_util'

class WpProtect < SecurityStressFramework
  def postLoadSociety
    run.society.each_node do |node|
      node.add_component('org.cougaar.core.security.services.wp.WPProtectionComponent') do |c|
        c.classname = 'org.cougaar.core.security.services.wp.WPProtectionComponent'
        c.insertionpoint = "Node.AgentManager.Agent.WPProtect"
        c.priority = "HIGH"
      end
    end
  end
  def postConditionalNextOPlanStage
    missing = getMissingAgents
    description="WP Protection Test"
    if (missing.empty?)
	success = true
    else
	success = false
    end
    saveResult(success, "WPProtection", "All agents registered with WP protection enabled")
    if (!missing.empty?) 
	summary("Missing Registered agents")
        summary(missing.join("\n"))
    end
  end
end
