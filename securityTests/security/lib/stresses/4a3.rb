
require 'security/lib/certRevocation'
require 'security/lib/dataProtection'
require 'security/lib/caDomain'

class Security4a3Experiment < SecurityStressFramework
   def initialize
      super
      @expiredAgent = nil
      @agent_node = nil
      @success = false
      @expiredIdmef = false
      @certRevocation = nil
   end


   def preTransformSociety
      @certRevocation = CertRevocation.new
      @agent_node = @certRevocation.selectNode

      @certRevocation.installExpirationPlugin(@agent_node)
   end

   def postLoadSociety
   end

   def postStartJabberCommunications
#      printDotsOnCougaarEvents
     on_cougaar_event do |event|
#       puts "event: #{event.cluster_identifier}, #{event.data}"

       if event.event_type == 'STATUS' && event.component == 'IdmefEventPublisherPlugin' && event.data =~ /DATA_FAILURE/

         if event.data =~ /Recovery failure:/ && event.data =~ /CertificateExpiredException/ &&  event.data =~ /SOURCE_AGENT:#{@expiredAgent}/
# /DATA_FAILURE_REASON,No certificates/
           summary"Detected rehydration failure event for expired agent #{@expiredAgent}"
           @success = true
           @expiredIdmef = true
         end # event.data
       end # event.event_type

     end # do
   end

#   def postConditionalStartSociety
   def postConditionalGLSConnection
        CaDomains.instance.ensureExpectedEntities

# 4A3, expire an agent and verify rehydration failure
        puts "Test rehydration for expired agents"
        @expiredAgent = @certRevocation.selectAgentFromNode(@agent_node)

# features supported only in the patch
      # set CA expiration period
        puts "Setting expiration to 10 minutes for agent #{@expiredAgent}."
        @certRevocation.setAgentExpiration(@expiredAgent, "10 m")

      # wait to generate snapshot
      sleep 10.minutes

# now check rehydration
      puts "Killing #{@expiredAgent}'s node (#{@agent_node.name})."
      run.do_action "KillNodes", @agent_node.name
      run.do_action "Sleep", 2.minutes

      puts "Restarting #{@expiredAgent}'s node (#{@agent_node.name})."
      run.do_action "RestartNodes", @agent_node.name

      Thread.fork {
        sleep 10.minutes
puts "checking status"
        summary "Failure to detect expired agent" unless @success
        saveResult(@success, "4a3", "Rehydration failure due to expired certificate")
        saveResult(@expiredIdmef, "4a22", "Idmef detection for 4a3")

        printSummary
#exit 0   # keep the society running so that we can re-run this.
      }
   end

   def postConditionalNextOPlanStage
      sleep 10.minutes
   end



end


