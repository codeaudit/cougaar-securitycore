
require 'security/lib/certRevocation'
require 'security/lib/dataProtection'
require 'security/lib/caDomain'

#
#
#
class Security4a1Experiment < SecurityStressFramework
   def initialize(run)
      super(run)
      @revokedAgent = nil
      @modifiedAgent = nil
      @revokeDetection = false
      @tamperDetection = false
      @revokedIdmef = false
      @tamperIdmef = false
   end



   def postStartJabberCommunications
#      printDotsOnCougaarEvents
     on_cougaar_event do |event|

       if event.event_type == 'STATUS' && event.component == 'IdmefEventPublisherPlugin' && event.data =~ /DATA_FAILURE/

         if event.data =~ /DATA_FAILURE_REASON,No certificates/
       puts "event: #{event.cluster_identifier}, #{event.data}"
           if event.data =~ /#{@revokedAgent}/
             summary "Detected rehydration failure event for revoked agent #{@revokedAgent}"
             @revokeDetection = true    
             @revokedIdmef = true
           end
         elsif event.data =~ /DATA_FAILURE_REASON:Verify digest failure/
       puts "event: #{event.cluster_identifier}, #{event.data}"
           if event.data =~ /#{@modifiedAgent}/
             summary "Detected rehydration failure event for agent #{@modifiedAgent} with persistent data modified"
             @tamperDetection = true
             @tamperIdmef = true
           end # if event
         end # elsif
       end # if event
     end # do event
   end

#   def postConditionalStartSociety
   def postConditionalGLSConnection
#   def postConditionalPublishNextStage
        CaDomains.instance.ensureExpectedEntities

# 4A2, revoke an agent and verify rehydration failure
#        sleep 10.minutes
 
        puts "Test rehydration for revoked and tampered agents"
        certRevocation = CertRevocation.new
        ra_node = certRevocation.selectNode
        @revokedAgent = certRevocation.selectAgentFromNode(ra_node)
#        certRevocation.revokeAgent(@revokedAgent)

        ma_node = certRevocation.selectNode
        @modifiedAgent = certRevocation.selectAgentFromNode(ma_node)

# give time to receive CRL
        sleep 10.minutes

# 4A1, modify one agent snapshot to verify signature      
        DataProtection.modifyPersistence(@modifiedAgent)

# now check rehydration
      run.do_action "KillNodes", ra_node.name, ma_node.name
      run.do_action "Sleep", 2.minutes

      run.do_action "RestartNodes", ra_node.name, ma_node.name

Thread.fork {
  sleep 5.minutes
#  summary "Failure to detect revoked agent rehydration" unless @revokeDetection
  summary "Failure to detect tampered agent rehydration" unless @tamperDetection
#  saveResult(@revokeDetection, "4a1", "Rehydration failure due to revoked certificate")
#  saveResult(@revokeIdmef, "4a20", "Idmef detection for 4a1")

  saveResult(@tamperDetection, "4a2", "Rehydration failure due to tampered persisted data")   
  saveResult(@tamperIdmef, "4a21", "Idmef detection for 4a2")

# exit 0   # keep the society running so that we can re-run this.
}
   end



   def printSummary
   end



end


