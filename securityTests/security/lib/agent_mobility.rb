
def getServlets(agent)
#  puts "getting servlets for agent #{agent}"
  if (agent.kind_of? String)
    agent = run.society.agents[agent]
  end
#  puts "getting servlets for agent #{agent.name}"
  url = agent.uri + "/list"
  getServletsFromURL(url, agent)
end

def getServletsFromURL(url,agent)
  if (agent.kind_of? String)
    agent = run.society[agent]
  end
#  puts "Trying to get list using URL #{url}"
  result, url2 = Cougaar::Communications::HTTP.get(url)
#  puts "Got response #{result}"
  servlets = []
  result.scan(%r@<li><a href="[^"]*">/\$#{agent.name}/([^<]+)</a></li>@) { |match|
    servlets << match[0]
  }
#  puts result
  servlets
end # getServletsFromURL

def getNode(agent)
  if (agent.kind_of? String)
    agent = run.society.agents[agent]
  end
  url = agent.uri + "/agents"
  result, url2 = Cougaar::Communications::HTTP.get(url)
  
  agents = []
  result.scan(%r@<a href="[^"]*">([^<]+)</a>@) { |match|
    agents << match[0]
  }
  # now go through all the nodes and find one that matches an agent in the list
  society.each_node { |node|
    agents.each { |agent|
      if (node.name == agent.name)
        return node
      end
    }
  }
  raise "Couldn't find the node in the society list."
end # getNode

def waitForAgentStart(maxWait, agents)
  if (agents.kind_of? Array)
    agentList = agents
  else
    agentList = []
    agentList << agents
  end
  return true if agentList.empty?

  agents = {}
  agentList.each { |agent| 
    if agent.kind_of? String
      agentName = agent
    else
      agentName = agent.name
    end
    agents[agentName] = agentName
  }

#  puts "Agent list = #{agentList.join(' ')}"
  cond = ConditionVariable.new
  mutex = Mutex.new
  Thread.fork {
    sleep(maxWait)
    mutex.synchronize {
      cond.signal
    }
  }

  mutex.synchronize {
    listener = run.comms.on_cougaar_event { |event|
=begin
      if (event.component == "SimpleAgent") 
        match = /.*AgentLifecycle\(([^\)]*)\) Agent\(([^\)]*)\) Node\(([^\)]*)\) Host\(([^\)]*)\)/.match(event.data)
        if match && match[1] == "Started" && agents[match[2]] != nil
=end
    if event.component=="SimpleAgent" || event.component=="ClusterImpl"
        match = /.*AgentLifecycle\(([^\)]*)\) Agent\(([^\)]*)\) Node\(([^\)]*)\) Host\(([^\)]*)\)/.match(event.data)
      if match
puts "match : #{match}"
puts "event #{event.data}"
        cycle, agent, node, host = match[1,4]
        if cycle == "Started" && @run.society.agents[agent] && node != @run.society.agents[agent].node.name

          puts "Got match! #{match[0]} #{match[1]} #{match[2]} #{match[3]} #{match[4]}"
          agents.delete(match[2])
#            puts "deleting #{match[2]}"
          if agents.empty?
#              puts "all done!"
            mutex.synchronize {
              cond.signal
            }
          end #if agents
        end # if cycle
      end # if match
    end # if event
    }
    cond.wait(mutex) if !agents.empty?
    run.comms.remove_on_cougaar_event(listener)
  }
#  puts "returning... #{agents.empty?}"
  return agents.empty?
end # waitForAgentStart

def waitForSingleAgentStart(maxWait, agent)
#  puts("maxWait = #{maxWait}, agent = #{agent}")
  if ! (agent.kind_of? String)
    agent = agent.name
  end
  cond = ConditionVariable.new
  mutex = Mutex.new
  Thread.fork {
    sleep(maxWait)
    mutex.synchronize {
      cond.signal
    }
  }

  node = nil
  mutex.synchronize {
    listener = run.comms.on_cougaar_event { |event|
      if (event.component == "SimpleAgent") 
        match = /.*AgentLifecycle\(([^\)]*)\) Agent\(([^\)]*)\) Node\(([^\)]*)\) Host\(([^\)]*)\)/.match(event.data)
        if match && match[1] == "Started" && match[2] == agent
#          puts "Got match! #{match[0]} #{match[1]} #{match[2]} #{match[3]} #{match[4]}"
          node = match[3]
          mutex.synchronize {
            cond.signal
          }
        end
      end
    }
    cond.wait(mutex) if node == nil
    run.comms.remove_on_cougaar_event(listener)
  }
  return node
end # waitForSingleAgentStart

def waitUntilAgentReady(maxWait, agent, node = nil)
#  puts("in waitUntilAgentReady = maxWait = #{maxWait}, agent = #{agent}, node = #{node}")
  startTime = Time.now

  if agent.kind_of? String
    agent = run.society.agents[agent]
  end

  if node == nil
#    puts "Waiting for agent #{agent.name} to start"
    node = waitForSingleAgentStart(maxWait, agent)
#    puts "Found node = #{node}"
  end

  if node.kind_of? String
    node = run.society.nodes[node]
  end

#  puts "Looking for the move to new node in the white pages"
  inWP = false
  while (Time.now - startTime < maxWait && !inWP)
    begin
      url = agent.uri
      url = url + "/agents"
      result, url = Cougaar::Communications::HTTP.get(url)
      puts "url = #{url}" if $COUGAAR_DEBUG
      puts "result = #{result}" if $COUGAAR_DEBUG
      puts "looking for #{node.name}" if $COUGAAR_DEBUG
      if result && result =~ />#{node.name}</
        inWP = true
      else
        sleep(10.seconds)
      end
    rescue
      puts "Not ready yet!"
      sleep 10.seconds
    end
  end
  if !inWP
    return false
  end

  # connect to the agent and try to send a message
  target = nil
  run.society.each_agent(true) { |a|
    if a.node != agent.node
      target = a
      break
    end
  }
  watcher = sendRelay(agent, target)
  while (Time.now - startTime < maxWait && 
         watcher.getArray().length < 4)
    sleep(10.seconds)
  end
  watcher.stop
  watcher.getArray().length == 4
end


def moveAgent(agent, node, maxWait = 10.minutes)
  if agent.kind_of? String
    agent = run.society.agents[agent]
  end
  if node.kind_of? String
    node = run.society.nodes[node]
  end
#  puts "About to move agent #{agent.name} to node #{node.name}"
  url = "#{agent.node.agent.uri}/move?op=Move&mobileAgent=#{agent.name}&originNode=&destNode=#{node.name}&isForceRestart=false&action=Add"
#puts "moveAgent url: #{url}"
#  result = Cougaar::Communications::HTTP.get(url)
#  raise_failure "Error moving agent" unless result
  result = getHtml(url)
#puts result.body
  raise_failure "Error moving agent" unless result.status==200
#  run.do_action "MoveAgent", agentName, nodeName
#  puts "Done with move agent #{agent.name} to node #{node.name}"
#  puts("Calling waitUntilAgentReady with maxWait = #{maxWait} and agent = #{agent}")
  waitUntilAgentReady(maxWait, agent)
end # moveAgent

def restartAgent(agent, node, maxWait = 20.minutes)
  if !moveAgent(agent, node, maxWait)
    return false
  end
  restartAgents(node, maxWait)
  waitUntilAgentReady(maxWait, agent, node)
end # restartAgent

def restartAgents(node, maxWait = 20.minutes)
  if node.kind_of? String
    node = society.nodes[node]
  end
  nodeName = node.name

  agents = node.agents.clone
  run['node_controller'].kill_node(self, node)
#  run.do_action "KillNodes", nodeName

  waitForAgentStart(maxWait, agents)
end # restartAgent

def rebootAgent(agent, tempNode, maxWait = 10.minutes)
  if !moveAgent(agent, tempNode, maxWait)
    return false
  end
  rebootAgents(tempNode, maxWait)
  waitUntilAgentReady(maxWait, agent, node)
end # restartAgent

def rebootAgents(node, maxWait = 10.minutes)
  if node.kind_of? String
    node = society.nodes[node]
  end
  nodeName = node.name
  agents = []
  node.agents.each { |agent|
    agents << agent
  }
  agents << node.agent
  run['node_controller'].kill_node(self, node)
#  run.do_action "KillNodes", nodeName
  # wait for it to die
  sleep 10.seconds
  # now try to restart it
  run['node_controller'].restart_node(self, node)
#  run.do_action "RestartNodes", nodeName
#  waitForAgentStart(maxWait, agents)
  
end # rebootAgents

