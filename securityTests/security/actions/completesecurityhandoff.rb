#!/usr/bin/ruby

require 'security/lib/web'

module Cougaar
  module Actions
    class CompleteSecurityHandOff < Cougaar::Action
      def initialize(run,nodename,communityname)
        super(run)
        @run=run
        @currentnodename = nodename
        @currentcommunityname = communityname
        @partialurl= "/handoffUnRegistration"
      end

      def perform
        @run.society.each_node do |node|
          if(node.name == @currentnodename)
            node.each_agent do |agent|
               uri = agent.uri + @partialurl
              puts"#{uri}";
              register uri
            end
             nodeuri="#{node.uri}/$#{node.name}"+ @partialurl
             register nodeuri 
          end
        end
      end

     def register (url)
       params = []
       params << "SecurityCommunity=6"
       params << "Enclave=#{@currentcommunityname}"   
       puts "Re register called with new enclave #{@currentcommunityname}"
       logInfoMsg "Starting handoff at : #{url} params #{params}" if $VerboseDebugging
       response =  SRIWeb.instance.postHtml url, params
     end
    end
  end #module Actions
end # module Cougaar
