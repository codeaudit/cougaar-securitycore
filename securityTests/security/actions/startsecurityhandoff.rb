#!/usr/bin/ruby

require 'security/lib/web'

module Cougaar
  module Actions
    class StartSecurityHandOff < Cougaar::Action
      def initialize(run,nodename)
        super(run)
        @run=run
        @currentnodename = nodename
        @partialurl= "/handoffUnRegistration"
      end

      def perform
        startDeRegistration
      end

     def startDeRegistration 
        @run.info_message (" startDeRegistration of security handoff called")
        @run.society.each_node do |node|
          if(node.name == @currentnodename)
	     @run.info_message ("Currentnode name : #{@currentnodename} ")
	     @run.info_message ("Node name :#{node.name}")	
             node.each_agent do |agent|
             uri = agent.uri + @partialurl
             puts"#{uri}";
             deregister uri
           end
            nodeuri="#{node.uri}/$#{node.name}"+ @partialurl
             @run.info_message( "Node uri #{nodeuri}")
            deregister nodeuri 
          end
        end
     end

     def deregister (url)
       params = []
       params << "Sensor=1"
       params << "CRL=2"
       params << "SecurityCommunity=3"
       @run.info_message "De register called "
       @run.info_message "Starting handoff at : #{url} params #{params}" 
       response =  SRIWeb.instance.postHtml url, params
       @run.info_message ("Response code: #{response.code}")
       @run.info_message ("Response body: #{response.body}")
     end

   end
  end #module Actions
end # module Cougaar
