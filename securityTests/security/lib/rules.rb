=begin
This file provides rules to run against an already loaded society.
=end

#class AbstractExperimentFramework
   def installHttps(port=8443)
      logInfoMsg "Adding https to all nodes"
      eachNode do |node|
         node.override_parameter("-Dorg.cougaar.lib.web.https.port", port.to_s)
         node.override_parameter("-Dorg.cougaar.lib.web.https.factory", "org.cougaar.core.security.ssl.WebtomcatSSLServerFactory")
      end
   end

  def installIdmefPlugin
      logInfoMsg "Installing IDMEF plugin"
      eachNodeAgent do |agent|
         agent.add_component do |c|
            c.classname = "org.cougaar.core.security.monitoring.plugin.IdmefEventPublisherPlugin"
         end
      end
   end

   def printDotsOnCougaarEvents(pattern=nil)
      logInfoMsg "Will print dots on Cougaar events"
      onCougaarEvent do |event|
         if pattern
            e = event.to_s
            if pattern =~ e
               puts
               puts e
            else
               print "."
               STDOUT.flush
            end
         else
            print "."
            STDOUT.flush
         end
      end
   end




   def getAgent(agentName)
      run.society.agents[agentName]
   end

   def eachNodeAgent(&block)
      run.society.each_node_agent() do |agent|
         yield agent
      end
   end

   def eachHost(&block)
      run.society.each_host do |host|
         yield host
      end
   end

   def eachNode(&block)
      eachHost do |host|
         host.each_node do |node|
            yield node
         end
      end
   end

   def eachAgent(&block)
      eachNode do |node|
         node.each_agent do |agent|
            yield agent
         end
      end
   end
   
   def runCommandAux(agent, command)
      case agent.class
      when String   # assume it is the host name
         host = getHost agent
      when Cougaar::Multifaceted::Host
         host = agent
      when Cougaar::Multifaceted::Agent
         host = agent.host
      end
      controller.acme_command(host, "rexec", command)
   end
   
   def runCommand(agent, command)
      runCommandAux agent, "\"#{command}\""
   end
   
   def runCommandAs(agent, user, command)
      runCommand agent, "su -l #{user} -c #{command}"
   end

   def on_cougaar_event(&block)
      run.comms.on_cougaar_event do |event|
         yield event
      end
   end

   alias onCougaarEvent on_cougaar_event

=begin
# The code below has been moved to a rule
   def installConfigReaderServlet
     run.society.each_agent(true) { |agent|
       agent.add_component { |c|
         c.classname = "org.cougaar.core.security.test.ConfigReaderServlet"
       }
     }
   end

   def installCodeRunnerServlet
     run.society.each_agent(true) { |agent|
       agent.add_component { |c|
         c.classname = "org.cougaar.core.security.test.RunCodeServlet"
       }
     }
   end

   def installSendMessageServlet
     run.society.each_agent(true) { |agent|
       agent.add_component { |c|
         c.classname = "org.cougaar.core.security.test.message.SendMessageComponent"
       }
     }
   end

   def installAttackHost
    run.society.each_host { |host|
      if host.has_facet? "attacker"
        return host
      end
    }
     # search for the first non-nameserver host and make it the attacker
     run.society.each_host { |host|
       facet_ok = true
       host.each_facet("service") { |facet|
         if (facet["service"] == "nameserver")
           facet_ok = false;
           break
         end
       }
       if (facet_ok) 
         host.add_facet({"attack" => "true"})
         return host
       end
     }
     
     # fine! we'll add it to the nameserver host
     run.society.each_host { |host|
       host.add_facet({"attack" => "true"})
       return host
     }
     raise "There are no hosts in the society"
   end
#end

=end 

#==============================================================#

class Regexp
   def on_cougaar_event(&block)
      run.comms.on_cougaar_event do |event|
         eventStr = event.to_s
         if self =~ eventStr
#puts '*************************************************'
#puts self.inspect
#puts eventStr
            yield event
         end
      end
   end

   alias onCougaarEvent on_cougaar_event
end

#class AbstractStressFramework
   def on_cougaar_event(&block)
      run.comms.on_cougaar_event do |event|
         yield event
      end
   end

   alias onCougaarEvent on_cougaar_event

   def onCaptureIdmefs(&block)
      /idmef/i.onCougaarEvent do |event|
         yield event
      end
   end
   
   def storeIdmefs(filename="#{$CIP}/workspace/log4jlogs/idmefs")
      unless $StoringIdmefListener
         $StoringIdmefListener = onCaptureIdmefs do |event|
            File.open(filename, 'a') do |file|
               Marshal.dump(event, file)
            end
         end
      end
   end
#end


module Cougaar
 module Model
   module Multifaceted
      attr_accessor :enclave
      def getComponentsMatching(componentPattern)
         components = []
         each_component do |component|
               components << component if component.classname =~ componentPattern
         end
         return components
      end
      def getCaAgent
         component = getComponentsMatching(/AutoConfigPlugin/)[0]
         # 1st arg is something like: sv041:ConusEnclaveCaManager:8810:9810
         argument = component.arguments[0] 
         run.society.agents[argument.to_s.split(':')[1]]
      end
   end
   
   class Agent
      def getCaAgent
         node.getCaAgent
      end
   end

 end # module Model


 module Actions
   class StoreIdmefs < Cougaar::Action
      def perform
         storeIdmefs
      end
   end
 end # module Actions
end # module Cougaar
