Cougaar::Model::Society.new('ACME-PING-SOCIETY') do |society|
  society.add_host('localhost') do |host|
    host.add_node('localnode') do |node|
      node.classname = 'org.cougaar.bootstrap.Bootstrapper'
      node.add_parameter('-Dorg.cougaar.node.name=localnode')
      node.agent.add_component('org.cougaar.community.CommunityPlugin()') do |c|
        c.classname = 'org.cougaar.community.CommunityPlugin'
        c.priority = 'COMPONENT'
        c.insertionpoint = 'Node.AgentManager.Agent.PluginManager.Plugin'
      end
      node.agent.add_component('org.cougaar.core.mobility.service.RootMobilityPlugin()') do |c|
        c.classname = 'org.cougaar.core.mobility.service.RootMobilityPlugin'
        c.priority = 'COMPONENT'
        c.insertionpoint = 'Node.AgentManager.Agent.PluginManager.Plugin'
      end
      node.agent.add_component('org.cougaar.mts.std.StatisticsPlugin') do |c|
        c.classname = 'org.cougaar.mts.std.StatisticsPlugin'
        c.priority = 'COMPONENT'
        c.insertionpoint = 'Node.AgentManager.Agent.PluginManager.Plugin'
      end
      node.agent.add_component('org.cougaar.core.thread.TopPlugin') do |c|
        c.classname = 'org.cougaar.core.thread.TopPlugin'
        c.priority = 'COMPONENT'
        c.insertionpoint = 'Node.AgentManager.Agent.PluginManager.Plugin'
      end
      node.agent.add_component('org.cougaar.core.thread.AgentLoadRatePlugin') do |c|
        c.classname = 'org.cougaar.core.thread.AgentLoadRatePlugin'
        c.priority = 'LOW'
        c.insertionpoint = 'Node.AgentManager.Agent.PluginManager.Plugin'
      end
      node.add_agent('AgentA') do |agent|
        agent.classname='org.cougaar.core.agent.SimpleAgent'
      end
      node.add_agent('AgentB') do |agent|
        agent.classname='org.cougaar.core.agent.SimpleAgent'
      end
      node.add_agent('AgentC') do |agent|
        agent.classname='org.cougaar.core.agent.SimpleAgent'
      end
    end
  end
end
