require "framework/cougaarMods"

def getRegisteredAgents
  nameServers = run.society.name_servers
  result = nil
  loop = true
  i = 0
  while (loop)
  nameServers.each { |nameServer|
    result, url = Cougaar::Communications::HTTP.get("#{nameServer.uri}/agents?suffix=.")
    break if result != nil
  }
  if (i > 5 || result != nil) 
     loop = false;
  else
    sleep 5.seconds
  end
  end
  return [] if result == nil
  re = /<a\s+href\s*=\s*"\/\$[^\/]*\/list"\s*>([^<]*)</
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
#    puts "running test agents"
    sleep delay
    expected = getExpectedAgents
#    puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
#    puts "Expected Agents"
#    puts expected.join("\n")
#    puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
    loop = true
    while (loop)
      registered = getRegisteredAgents
      missing = expected - registered
#      puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
#      puts "Missing Agents"
#      puts missing.join("\n")
#      puts "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*"
      if block_given?
        yield(missing, expected)
#      else
#        puts "#{Time.now} Agents missing: #{missing.length}"
      end
      if (missing.empty?)
        loop = false
      else
        sleep interval
      end
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
              result, url = Cougaar::Communications::HTTP.get("#{server.uri}/agents?suffix=.", 1.minute)
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
      def initialize(run, interval = 2.minutes, delay = 1.minutes)
        super(run)
        @interval = interval
        @delay = delay
      end #initialize

      def perform
#puts "#{Time.now} starting test of WP Registration"
        lastCheck = -1
        testAgentRegistrations(@interval, @delay) { |missing, expected|
#puts "#{Time.now} WP Registration: callback"
          if missing.empty?
            @run.info_message("All agents have registered to the white pages")
#            puts("All agents have registered to the white pages")
          else
            if (lastCheck == missing.length)
              @run.warn_message("No new agents have registered to the white pages for #{interval} seconds")
#              puts("No new agents have registered to the white pages for #{interval} seconds")
            end
            @run.info_message("Agents who haven't registered with the white pages: #{missing.join(" ")}")
            @run.info_message("Agents who have registered with the white pages: #{(expected - missing).join(" ")}")
#            puts("#{Time.now} Agents who haven't registered with the white pages: #{missing.join(" ")}")
#            puts("#{Time.now} Agents who have registered with the white pages: #{(expected - missing).join(" ")}")
          end
          lastCheck = missing.length
        }
      end #perform
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
