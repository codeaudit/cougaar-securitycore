
##
#  <copyright>
#  Copyright 2003 SRI International
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#

require 'framework/security'
require 'framework/certAuthority'

#require 'runSome'

$ExperimentName = 'JTG-Security-7a'
$ExperimentClass = 'Security7aExperiment'

class Security7aExperiment < SecurityExperimentFramework
   def initialize
      super
      @name = 'CSI-Security-7a'
      @experiments = [Csi7a]
   end

def postPublishGLSRoot2
#postStartJabberCommuncations
   postOPlanReady
end

   def postLoadSociety
#   def postLoadSociety
#puts 'writing society to ruby file'
#society = run.society.to_ruby
#f = File.new('ACME-TEST.rb', 'w')
#f.puts society
#f.close
#exit
      #super
      #addHttps
      getNodeInfoFromSociety
   end

   def postStartJabberCommunications
#      printDotsOnCougaarEvents
#     on_cougaar_event do |event|
#       puts event.to_s
#     end
   end

   def postConditionalStartSociety
      # Give the agents time to retrieve their certificates
      sleep 10.minutes unless $WasRunning
      checkPersistence
      printSummary
exit 0   # keep the society running so that we can re-run this.
   end

   def checkPersistence
     run.society.each_host do |host|
       host.each_node do |node|
         # list of agents 
         entities = node.agents.collect {|agent| agent.name}
         entities << node.name
         puts "doing #{node.name}"

         port = getParameter(node, /http.port/, nil)
# request to get persistence status
         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
         puts "#{url.to_s}"
         response = getHtml(url)
         puts "#{response.to_s}"
# collect all agents that has persisted
      agentPattern = /<\/TD><TD>([^<]*)<\/TD><TD>OUTPUT_COMPLETE/im
         agents = response.body.scan(agentPattern).collect {|i| i.to_s}
# compare with entities
	 missing = entities - agents

         if missing != []
           summary "#{node.name} missing agents for persistence:"
           summary missing.as_string
         else
           summary "#{node.name} all agents persisted"
         end
         
       end # each node
     end # each host
   end

      # get parameter from node given param name
      def getParameter(node, paramName, default)
        node.each_parameter do |p|
          (name, value) = p.to_s.split('=')
          return value if name =~ paramName
        end

        puts "No parameter found for #{paramName} on #{node.name}"
        return default
      end


   def printSummary
   end

   def postPlanningComplete
     checkPersistenceRecovery
   end

   def checkPersistenceRecovery
# check if there is any recovery request
     run.society.each_host do |host|
       host.each_node do |node|

         port = getParameter(/http.port/, node, nil)
# request to get persistence status
         url = "http://#{host.name}:#{port}/$#{node.name}/PersistenceVerificationServlet"
         response = getHtml(url)
# collect all agents that has rehydrated
      requestPattern = /<\/TD><TD>([^<]*)<\/TD><TD>RECOVERY_REQUEST/im
         requestAgents = response.body.scan(requestPattern).collect {|i| i.to_s}
      recoveryPattern = /<\/TD><TD>([^<]*)<\/TD><TD>KEY_RECOVERED/im
         recoverAgents = response.body.scan(recoveryPattern).collect {|i| i.to_s}
# compare with entities
         if requestAgents != []
           missing = requestAgents - recoveryAgents
           if missing != []
             summary "#{node.name} missing agents for recovery:"
             summary missing.as_string
           else
             summary "#{node.name} all agents has recovered:"
             summary recoveryAgents.as_string
           end
         end 
       end # each node
     end # each host


# if so check recovery status
     
   end 

end


class Csi7a < SecurityStressFramework
   def postOPlanReady(env)
   end
end
