#!/usr/bin/ruby

society.each_node do |node|
  node.add_component do |c|
    c.insertionpoint="Node.AgentManager.Agent.MessageTransport.Component"
    c.classname = "org.cougaar.mts.std.DestinationQueueMonitorPlugin"
  end
end

