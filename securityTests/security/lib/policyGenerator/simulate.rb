CIP = ENV['CIP']
DATASET=ARGV[0]


$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require 'cougaar/communities' 
require 'security/scripts/setup_scripting'
require 'security/lib/common_security_rules'
require "#{DATASET}/Sending.rb"
require "commPolicy.rb"

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging

include Cougaar


def getAgentEnclaveFromName(run, name)
  run.society.each_agent(true) do |agent|
    if agent.name == name then
      return agent.host.enclave
    end
  end
  return "Unknown"
end

def checkPolicy(run, p)
  allAgents=[]
  agentOutside = false
  run.society.each_agent(true) do |agent|
    allAgents.push(agent.name)
  end
  $messages.each do |message|
    sender, receiver = message
    if allAgents.include?(sender) && allAgents.include?(receiver) then
      if !p.isMsgAllowed(sender, receiver) then
        puts("#{sender} shouldn't be talking  to #{receiver}")
      end
    elsif !agentOutside then
      puts "Found an agent outside the society (either #{sender} or #{receiver})"
      agentOutside  = true
    end
  end
end

def analyzeNodes(run, p)
  allNodes = []
  nodeCommHash = Hash.new()
  run.society.each_node do |node|
    allNodes.push(node.name)
    nodeCommHash[node.name] = []
  end
  $messages.each do |message|
    sender, receiver = message
    if !p.isMsgAllowed(sender, receiver) then
      if allNodes.include?(sender) && 
         !nodeCommHash[sender].include?(receiver)  then
        nodeCommHash[sender].push(receiver)
      elsif allNodes.include?(receiver) && 
            !nodeCommHash[receiver].include?(sender)  then
        nodeCommHash[receiver].push(sender)
      end
    end
  end
    nodeCommHash.each_key() do |node|
    puts("The node, #{node}, in enclave, " +
         "#{getAgentEnclaveFromName(run, node)} is talking to")
    nodeCommHash[node].each() do |agent|
      puts("\tthe agent, #{agent} in enclave, " + 
            "#{getAgentEnclaveFromName(run,agent)}")
    end     
  end 
end


Cougaar.new_experiment("Test").run(1) do
  do_action "LoadSocietyFromScript",  "#{DATASET}/mySociety.rb"
  do_action "GenericAction" do |run|
    run.society.communities =
          Cougaar::Model::Communities.from_xml_file(run.society, 
                                                    "#{DATASET}/myCommunities.xml")
  end
#  do_action "LoadCommunitiesFromXML", "#{DATASET}/myCommunities.xml"
  do_action "SaveCurrentCommunities", "#{DATASET}/mySaveCommunities.xml" 

  do_action "GenericAction" do |run|
    begin 
      p = CommPolicy.new(run)
#      load 'debug.rb'
      p.allowNameService()
      puts "Count = #{p.policyCount} after Name Service"
      p.allowSpecialCommunity()
      puts "Count = #{p.policyCount} after Community"
      p.allowSecurityManagement()
      puts "Count = #{p.policyCount} after Security"
      p.allowSuperiorSubordinate()
      puts "Count = #{p.policyCount} after Superior/Subordinate"
      p.allowInterMnR()
      puts "Count = #{p.policyCount} after InterMNr"
      p.allowServiceProviders
      puts "Count = #{p.policyCount} after Service Providers"
#      load "debug.rb"
      checkPolicy(run, p)
      puts "Density = #{100 * p.density}"
#      analyzeNodes(run, p)
    rescue => ex
      puts "Exception found = #{ex}, trace = #{ex.backtrace().join("\n")}"
    end
  end
end


