#!/usr/bin/ruby

society.each_node do |node|
  node.agent.add_component do |c|
    c.name = "org.cougaar.mts.std.DestinationQueueMonitorPlugin"
    c.insertionpoint = "Node.AgentManager.Agent.MessageTransport.Component"
    c.classname = "org.cougaar.mts.std.DestinationQueueMonitorPlugin"
  end
end

