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

def checkPolicy(run, p)
  allAgents=[]
  counter = 0
  agentOutside = false
  run.society.each_agent(true) do |agent|
    allAgents.push(agent.name)
  end
  $messages.each do |message|
    sender, receiver = message
    if allAgents.include?(sender) && allAgents.include?(receiver) then
      if !p.isMsgAllowed(sender, receiver) then
        puts("#{sender} shouldn't be talking  to #{receiver}")
        counter += 1
      end
    elsif !agentOutside then
      puts "Found an agent outside the society (either #{sender} or #{receiver})"
      agentOutside  = true
    end
  end
  counter
end

def tally(p, s)
  if true
    puts "#{s}: Count = #{p.policyCount}, Density = #{p.density}"
  end
end


def installPolicies(p)
  p.allowNameService()
  tally(p,"name service")
  p.allowSpecialCommunity()
  tally(p, "community")
  p.allowSecurityManagement()
  tally(p, "Security")
  p.allowSuperiorSubordinateLinear()
  tally(p, "Subordinates")
  p.allowInterMnR()
  tally(p, "Monitoring")
  p.allowServiceProviders()
  tally(p, "Service")
  p.allowTalkToSelf()
  tally(p, "Mumble")
  p.policyCount()
end

Cougaar.new_experiment("Test").run(1) do
  do_action "LoadSocietyFromScript",  "#{DATASET}/mySociety.rb"
  do_action "GenericAction" do |run|
    run.society.communities =
          Cougaar::Model::Communities.from_xml_file(run.society, 
                                                    "#{DATASET}/myCommunity.xml")
  end
#  do_action "LoadCommunitiesFromXML", "#{DATASET}/myCommunity.xml"
  do_action "SaveCurrentCommunities", "#{DATASET}/mySaveCommunity.xml" 

  do_action "GenericAction" do |run|
    begin 
      p = CommPolicy.new(run)
#      load 'debug.rb'
      installPolicies(p)
      puts "#{checkPolicy(run, p)} bad communication paths"
#     load "debug.rb"
      puts "Density = #{100 * p.density}"
    rescue => ex
      puts "Exception found = #{ex}, trace = #{ex.backtrace().join("\n")}"
    end
  end
end


