require "cgi"
require 'security/lib/policy_util'

# The section contains the additions or modifications to the existing ACME environment.

module Cougaar
   # myexperiment is the current AbstractExperimentFramework instance.
   # Note that it is a class variable, meaning only one environment may be
   # run at a time (though this one instance may have multiple experiments)
   def self.myexperiment
      return $Myexperiment
   end
   def self.myexperiment=(experiment)
      $Myexperiment = experiment
   end

   # myrun contains the current Run instance.  It is also a class variable.
   def self.getRun
      $Myrun
   end
   def self.setRun(run)
      $Myrun = run
   end

   class Run
      def elapsed_time
         puts 'in elapsed_time'
      end
   end

   # Identical to the original initialize, except 'run' is now a class variable
   # in the Cougaar module.
   class MultiRun
      def initializeee(experiment, run_count, &block)
         @run_count = run_count
         @interrupted = false
         @experiment = experiment
         @run_count.times do |count|
            run = Run.new(self, count)
            Cougaar.setRun(run)
            Cougaar.getRun.define_run &block
            Cougaar.getRun.start
            return if interrupted?
         end
      end
   end


=begin
   class Action
      def doPreFunctions(action, *args)
         a = action.to_s.split('::')[-1]
         a = a.split('(')[0]
         Cougaar.myexperiment.doExperimentMethod 'pre'+a
      end
      def doPostFunctions(action, *args)
         a = action.to_s.split('::')[-1]
         a = a.split('(')[0]
         Cougaar.myexperiment.doPostExperimentMethod 'post'+a
      end
   end

   class State
      def doPreFunctions(state, *args)
         s = state.to_s.split('::')[-1]
         s = s.split('(')[0]
         Cougaar.myexperiment.doExperimentMethod 'pre'+s
      end
      def doPostFunctions(state, *args)
         s = state.to_s.split('::')[-1]
         s = s.split('(')[0]
         Cougaar.myexperiment.doPostExperimentMethod 'post'+s
      end

      def process
      end
   end

=end

end

module Cougaar
   module States
     class OPlanReady < Cougaar::State
#       DEFAULT_TIMEOUT = 20.minutes
#       PRIOR_STATES = ["SocietyRunning"]
       def process
         while (!@run['OPlan Ready'])
           sleep 10.seconds
         end
       end
       def unhandled_timeout
         @run.do_action "StopSociety"
         @run.do_action "StopCommunications"
       end
     end # OPlanReady

     class UserManagerReady < Cougaar::State
=begin
       DEFAULT_TIMEOUT = 45.minutes
       PRIOR_STATES = ["SocietyRunning"]
       DOCUMENTATION = Cougaar.document {
         @description = "Waits for the user manager to be available to a particular agent."
         @parameters = [
           {:agent => "Agent to connect to -- default is 'NCA'"},
           {:path => "The uri path -- default is '/glsinit'"},
           {:timeout => "default = nil, Amount of time to wait in seconds."},
           {:block => "The timeout handler (unhandled: StopSociety, StopCommunications"}
         ]
         @example = "
           wait_for 'UserManagerReady'
             or
           wait_for 'UserManagerReady', 'FooAgent', 10.minutes
         "
       }
=end

       def initialize(run, agent="NCA", path="/userManagerReady", timeout=nil, &block)
         super(run, timeout, &block)
         @agent = agent
         @path = path
       end
       
       def process
         @run.info_message "Waiting for #{@agent} to be ready for user access"
         waitForUserManager(@agent, @path, '/move')
       end # perform

       def unhandled_timeout
         @run.do_action "StopSociety"
         @run.do_action "StopCommunications"
       end
     end # UserManagerReady
   end # module States
   
   module Actions
     class InstallOPlanWatcher < Cougaar::Action
       def perform
         @run['OPlan Ready'] = false
         listener = @run.comms.on_cougaar_event { |event|
           if event.event_type=="STATUS" && event.cluster_identifier=="NCA" && event.component=="OPlanDetector"
             @run['OPlan Ready'] = true
             @run.comms.remove_on_cougaar_event(listener)
           end
         }
       end
     end # InstallOPlanWatcher

      class SetAcmeUser < Cougaar::Action
        def perform
          user = ENV['USER']
          run.society.each_service_host("acme") { |host|
            run.comms.new_message(host).set_body("command[rexec_user]rm /tmp/*.xml.jar").request(30)
#            puts "Connecting to #{host.name} to set user to #{user}"
            http = Net::HTTP.new(host.name, 9444)
            response, result = http.get("/cougaar_config");
#            puts "result = #{result}"
            fields = parseFields(result)
            fields["cmd_user"] = user
#            fields["tmp_dir"] = "/tmp"
#            fields["tmp_dir"] = "/tmp/acme-#{user}"
            fields = makeParamString(fields)
#            puts("sending #{fields}")
            response, result = http.post("/cougaar_config", fields)
#            puts "result = #{result}"
#            return nil # all done!
          }
        end
        
        def parseFields(results)
          fields = {}
          results.scan(/<input[^>]*>/i) { |input|
            name = nil
            value = nil
#            puts("match = #{input}")
            input.scan(/\s+(\w+)\s*=\s*"([^"]*)"/) { |match|
              case match[0].downcase()
              when "name"
                name = match[1]
              when "value"
                value = match[1]
              end
            }
#            puts("#{name} = #{value}")
            if (name != nil && value != nil)
              fields[name] = value
            end
          }
          return fields
        end

        def makeParamString(hash)
          arr = []
          hash.each { |key,value|
            arr << "#{CGI::escape(key)}=#{CGI::escape(value)}"
          }
          arr.join("&")
        end
      end

     class SetAcmeParameters < Cougaar::Action
=begin
        DOCUMENTATION = Cougaar.document {
          @description = "Invoke ACME cougaar_config servlet to change parameters"
          @parameters = [
            {:args=> "optional, hash of arguments"}
          ]
          @example = "do_action 'SetAcmeParameters', {'cougaar_install_path' => '$COUGAAR_INSTALL_PATH'}"
        }
=end
# Parameters:
# cougaar_install_path, jvm_path, cmd_prefix, cmd_suffix, cmd_user, tmp_dir
        def initialize(run, args)
          super(run)
          @args = args
        end
        def perform
          run.society.each_service_host("acme") { |host|
            run.comms.new_message(host).set_body("command[rexec_user]rm /tmp/*.xml.jar").request(30)
#            puts "Connecting to #{host.name} to set user to #{user}"
            http = Net::HTTP.new(host.name, 9444)
            response, result = http.get("/cougaar_config");
#            puts "result = #{result}"
            fields = parseFields(result)
            @args.each_pair {|key, value|
              fields[key] = value
            }
#            fields["tmp_dir"] = "/tmp"
#            fields["tmp_dir"] = "/tmp/acme-#{user}"
            fields = makeParamString(fields)
#            puts("sending #{fields}")
            response, result = http.post("/cougaar_config", fields)
#            puts "result = #{result}"
#            return nil # all done!
          }
        end
        def parseFields(results)
          fields = {}
          results.scan(/<input[^>]*>/i) { |input|
            name = nil
            value = nil
#            puts("match = #{input}")
            input.scan(/\s+(\w+)\s*=\s*"([^"]*)"/) { |match|
              case match[0].downcase()
              when "name"
                name = match[1]
              when "value"
                value = match[1]
              end
            }
#            puts("#{name} = #{value}")
            if (name != nil && value != nil)
              fields[name] = value
            end
          }
          return fields
        end

        def makeParamString(hash)
          arr = []
          hash.each { |key,value|
            arr << "#{CGI::escape(key)}=#{CGI::escape(value)}"
          }
          arr.join("&")
        end
      end

      class PrintSummary < Cougaar::Action
        def perform
          pass = true
          $TestResults.each { |test|
            if !test[0]
              pass = false
            end
            success = "SUCCESS"
            if !test[0]
              success = "FAILURE"
            end
            @run.info_message [success, test[1], test[2]].join(" ")
          }
          if !pass
            @run.info_message "Summary Info"
            $SummaryMsgs.each { |msg|
              @run.info_message msg
            }
          end
          if !pass
            raise "The tests did not pass"
          end
        end
      end # PrintSummary
   end
end

=begin

module Cougaar
   module Actions
      class PreRun < Cougaar::Action
         def perform
            Cougaar.myexperiment.doExperimentMethod 'preRun'
         end
      end
      class PostRun < Cougaar::Action
         def perform
            Cougaar.myexperiment.doPostExperimentMethod 'postRun'
         end
      end
   end
end

=end

module Cougaar
  module Model
    class Society
      def each_agent_with_component(component, &block)
        each_agent(true) { |agent|
          agent.each_component { |c|
            if c.classname == component
              yield(agent)
              break
            end
          }
        }
      end # each_agent_with_component

      def agents_with_component(component)
        agents = []
        each_agent_with_component(component) { |agent|
          agents << agent
        }
        agents
      end # agents_with_component

      def name_servers
        nameServers = []
        each_node { |node|
          node.each_facet("role") { |facet| 
            if facet["role"].downcase() == "nameserver"
              nameServers << node
            end
          }
        }
	nameServers
      end # name_servers
    end # Society

    class Agent
      def enclave
        facet = @node.host.get_facet("enclave")
        if facet.kind_of? String
          return facet
        elsif facet.kind_of? Array
          return facet[0].to_s
        elsif facet.kind_of? Facet
          return facet.to_s
        end
      end # enclave

      def url
        # look for the name server
        nameServers = @node.host.society.name_servers
#          print("name server = #{nameServer.uri}\n");
        result = nil
	first = true
	url2 = nil
        while (result == nil)
	  nameServers.each { |nameServer|
	    begin
	      result, url2 = Cougaar::Communications::HTTP.get("#{nameServer.uri}/$#{@name}/list", 30.seconds)
	      if (result != nil && url2.to_s =~ /#{@name}\/list$/)
		break
	      end
	      if first
		sleep 10.seconds
		first = false
	      end
	    rescue Timeout::Error => e
	      puts e.message
	      puts e.backtrace.join("\n")
	      sleep 10.seconds
	    rescue Exception => e
	      puts e.message
	      puts e.backtrace.join("\n")
	      sleep 10.seconds
	    end
	  }
	  sleep 10.seconds
        end
#        raise "Could not reach name server" unless result
        url2 = url2.to_s
        url2[0..url2.length - 6] # eliminate the /list from the end
      end # url

      def is_ready?
        result = nil
	nameServers = @node.host.society.name_servers
        begin
          # look for the name server
	  nameServers.each { |nameServer|
	    result = Cougaar::Communications::HTTP.get("#{nameServer.uri}/agents?suffix=.", 30.seconds)
	  }
        rescue Timeout::Error => e
        rescue
	  # just try the next one
        end
        raise "Could not reach name server" unless result
        # now hunt through the results for the agent and return the result
        result =~ />\$#{agent}</
      end # is_ready?
    end # Agent
  end # Model
end # Cougaar
