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
        @run.info_message (" Perform of complete security handoff called")
        @run.society.each_node do |node|
          if(node.name == @currentnodename)
	     @run.info_message ("Currentnode name : #{@currentnodename} ")
	     @run.info_message ("Node name :#{node.name}")		
            node.each_agent do |agent|
               uri = agent.uri + @partialurl
               @run.info_message( "Agent uri #{uri}")
              register uri
            end
             nodeuri="#{node.uri}/$#{node.name}"+ @partialurl
	     @run.info_message( "Node uri #{nodeuri}")
             register nodeuri 
          end
        end
      end

     def register (url)
       params = []
       params << "SecurityCommunity=6"
       params << "Enclave=#{@currentcommunityname.capitalize}"   
       @run.info_message"Re register called with new enclave #{@currentcommunityname}"
       @run.info_message "Complete security handoff at : #{url} params #{params}" 
       response =  SRIWeb.instance.postHtml url, params
       @run.info_message ("Response code: #{response.code}")
       @run.info_message ("Response body: #{response.body}")	
     end
    end
  end #module Actions
end # module Cougaar
