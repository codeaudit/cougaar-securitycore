CIP = ENV['CIP']
DATASET=ARGV[0]


$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require 'cougaar/communities' 
require 'security/actions/policyGeneration.rb'
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
  if false
    puts "#{s}: Count = #{p.policyCount}, Density = #{100 * p.density}%"
  end
end

def irb(b)
  prompt = "-> "
  while TRUE
    print prompt
    output = nil
    begin
      input = $stdin.gets()
      if input == nil then
        break
      end
      puts eval(input, b)
    rescue => exception
      puts("#{exception} #{exception.backtrace.join("\n")}")
    end
    puts output
  end
  puts "Continuing..."
end

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging


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
      irb(binding)
      p = buildInitialUrPolicies(run,
                                 "society_config",
                                 "localhost",
                                 "s0c0nfig",
                                 "cougaar104")
      puts "#{checkPolicy(run, p)} bad communication paths"
      p.wellDefined?
      irb(binding)
      #load "debug.rb"
      #puts "Density = #{100 * p.density}%"
      p.writePolicies("#{DATASET}/policies")
    rescue => ex
      puts "Exception found = #{ex}, trace = #{ex.backtrace().join("\n")}"
    end
  end
end
