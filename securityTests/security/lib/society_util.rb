require "security/lib/cougaarMods"
require 'security/lib/getStackTrace'

def getRegisteredAgents
  nameServers = run.society.name_servers
  result = nil
  loop = true
  i = 0
  while (loop)
  nameServers.each { |nameServer|
    uri = "#{nameServer.uri}/agents?suffix=.&format=html&depth=-1&size=-1&time=50000&sorted=true&split=true"
    result, url = Cougaar::Communications::HTTP.get(uri)
    break if result != nil
  }
  if (i > 5 || result != nil) 
     loop = false;
  else
    sleep 5.seconds
  end
  end
  return [] if result == nil
  re = /<a\s+href\s*=\s*"\/\$([^\/]*)\/list"\s*>[^<]*</
  agents = result.scan(re)
  agents.collect { |a| a[0] }
end

def getExpectedAgents
  expected = []
  run.society.each_agent(true) { |agent|
    expected << agent.name
  }
  expected.sort
end

def getMissingAgents
  getExpectedAgents - getRegisteredAgents
end

def testAgentRegistrations(interval = 5.minutes, delay = 5.minutes)
#  puts "********************************************** testing agent fork"
  Thread.fork {
    begin
#    puts "running test agents"
        #logInfoMsg "sleep #{delay}"
      sleep delay
      expected = getExpectedAgents
#    puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
#    puts "Expected Agents"
#    puts expected.join("\n")
#    puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
      loop = true
      while (loop)
        #logInfoMsg "getRegisteredAgents"
        registered = getRegisteredAgents
        missing = expected - registered
#      puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
#      puts "Missing Agents"
#      puts missing.join("\n")
#      puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
        if block_given?
          yield(missing, expected)
        end
#        puts "#{Time.now} Agents missing: #{missing.length}"
        #logInfoMsg "sleep #{interval}"
        sleep interval
        #if (missing.empty?)
        #  loop = false
        #else
        #end
      end
    rescue => e
      saveAssertion "wp_registration", "Unable to check WP: #{e} #{e.backtrace.join("\n")}"
    end
  }
end

module Cougaar
  module Actions
    class CorrectURLs < Cougaar::Action
      def perform
        searchServers = @run.society.name_servers
        foundServer = nil
        run.society.each_node { |node|
          node.each_facet("role") { |facet| 
            role = facet["role"].downcase()
            if (role == "rootcertificateauthority" || role == "certificateauthority") &&
               !(searchServers.include? node)
              searchServers << node
            end
          }
        }
        while (foundServer == nil)
          searchServers.each { |server|
            begin
#puts "connecting to: #{server.uri}"
              uri = "#{server.uri}/agents?suffix=.&format=html&depth=-1&size=-1&time=50000&sorted=true&split=true"
              result, url = Cougaar::Communications::HTTP.get(uri, 2.minute)
              if result != nil
                # check that each node is registered
                allOk = true
                @run.society.each_node { |node|
                  if !(result =~ />#{node.name}</)
#puts "couldn't find #{node.name}"
#puts result
                    allOk = false
                    break
                  end
                }
                if allOk
                  foundServer = server
                  break
                end
              end
            rescue Timeout::Error
            rescue
            end
          }
          sleep 10.seconds if (foundServer == nil)
        end # while
        @run.society.each_node { |node|
          url = nil
          while (url == nil)
#puts "getting url for #{node.name}"
            result, url = Cougaar::Communications::HTTP.get("#{foundServer.uri}/$#{node.name}/list")
            if !(url.to_s =~ /\/list$/)
              url = nil
              sleep 10.seconds
            end
          end
          node.override_parameter("-Dorg.cougaar.lib.web.http.port", "#{url.port}")
#          puts "#{node.name} changed to #{url.port}"# if $COUGAAR_DEBUG
        }
      end # perform
    end # CorrectURLs

    class TestWPRegistration < Cougaar::Action
      def initialize(run, interval = 5.minutes, delay = 20.minutes)
        super(run)
        @interval = interval
        @delay = delay
        Cougaar::Actions::Stressors.addStressIds(['wp_registration'])
        @stackTrace = GetStackTrace.new(run)
      end #initialize

      def perform
#puts "#{Time.now} starting test of WP Registration"
        lastCheck = -1
        testAgentRegistrations(@interval, @delay) { |missing, expected|
#puts "#{Time.now} WP Registration: callback"
          if missing.empty?
            saveResult(true, "wp_registration", "All agents (#{expected.size}) have registered to the white pages")
#            puts("All agents have registered to the white pages")
          else
            if (lastCheck == missing.length)
              saveAssertion("wp_registration", "No new agents have registered to the white pages for #{@interval} seconds")
#              puts("No new agents have registered to the white pages for #{interval} seconds")
            else
              saveAssertion("wp_registration", "#{missing.size} agents haven't registered with the white pages: #{missing.join(" ")}")
              saveAssertion("wp_registration", "#{(expected - missing).size} agents have registered with the white pages: #{(expected - missing).join(" ")}")
            end
#            puts("#{Time.now} Agents who haven't registered with the white pages: #{missing.join(" ")}")
#            puts("#{Time.now} Agents who have registered with the white pages: #{(expected - missing).join(" ")}")
            # Get stack trace of agents that have not registered
            getStackTraceAgents(missing)
          end
          lastCheck = missing.length
        }
      end #perform

     def getStackTraceAgents(agents)
       # Create node list
       nodes = []
       agents.each { |agent|
         begin
           run.society.each_agent(true) { |socagent|
             #logInfoMsg "#{agent} - #{socagent.name}"
             if (socagent.name == agent)
                nodes = nodes | [socagent.node]
                break
             end
           }
         rescue => e
           saveAssertion "wp_registration", "Unable to find agent: #{agent} #{e} #{e.backtrace.join("\n")}"
         end
       }
       nodenames = []
       nodes.each {|node|
         nodenames << node.name
       }
       saveAssertion "wp_registration", "Nodes where agents are missing: #{nodenames.join(" ")}"
       nodes.each { |node|
         @stackTrace.getStack(node.name)
       }
     end #getStackTraceAgents

    end # class TestWPRegistration
  end # module Actions
end # module Cougaar

module Cougaar
   module States
     class AgentsRegistered < Cougaar::State
       DEFAULT_TIMEOUT = 45.minutes
       PRIOR_STATES = ["SocietyRunning"]

       def initialize(run, timeout=nil, &block)
         super(run, timeout, &block)
       end
       
       def process
         @run.info_message "Waiting for all agents to register with the white pages"
	 expected = getExpectedAgents
	 puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" if $COUGAAR_DEBUG
	 puts "Expected Agents" if $COUGAAR_DEBUG
	 puts expected.join("\n") if $COUGAAR_DEBUG
	 puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" if $COUGAAR_DEBUG
	 while (true)
	   registered = getRegisteredAgents
	   missing = expected - registered
	   puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" if $COUGAAR_DEBUG
	   puts "Missing Agents" if $COUGAAR_DEBUG
	   puts missing.join("\n") if $COUGAAR_DEBUG
	   puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*" if $COUGAAR_DEBUG
	   puts "#{Time.now} Agents missing: #{missing.length}" if $COUGAAR_DEBUG
	   if (missing.empty?)
	     return true
	   end
	   sleep 30.seconds
	 end
       end # perform

       def unhandled_timeout
         @run.do_action "StopSociety"
         @run.do_action "StopCommunications"
       end
     end # UserManagerReady
   end # module States
end
