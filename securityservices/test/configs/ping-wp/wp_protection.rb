
module Cougaar
  module Actions
    class AddWPProtection < Cougaar::Action
      def initialize(run)
	super(run)
      end
      def perform
	@run.society.each_node do |node|
	  node.add_component('org.cougaar.core.security.services.wp.WPProtectionComponent') do |c|
	    c.classname = 'org.cougaar.core.security.services.wp.WPProtectionComponent'
	    c.insertionpoint = "Node.AgentManager.Agent.WPProtect"
            c.priority = "HIGH"
          end
        end
      end
    end
    class AddWPTest < Cougaar::Action
      def initialize(run, agent, role)
        super(run)
	@agent = agent
	@role = role
      end
      def perform
        testAgent = @run.society.agents[@agent]
        if !testAgent
           raise "Agent #{@agent} does not exist in society"
        end
        testAgent.add_component('org.cougaar.core.security.test.wp.WPTestServlet') do |c|
          c.classname = 'org.cougaar.core.security.test.wp.WPTestServlet'
        end
	testAgent.add_component('org.cougaar.core.security.test.wp.WPTestPlugin') do |c|
	  c.classname = 'org.cougaar.core.security.test.wp.WPTestPlugin'
          c.add_argument("#{@role}")
        end
      end
    end
  end
end

