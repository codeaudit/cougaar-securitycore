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
       @run.society.each_node do |node|
          if(node.name == @currentnodename)
            node.each_agent do |agent|
              uri = agent.uri + @partialurl
              puts"#{uri}";
              deregister uri
            end
            nodeuri="#{node.uri}/$#{node.name}"+ @partialurl
             deregister nodeuri 
          end
        end
     end

     def deregister (url)
       params = []
       params << "Sensor=1"
       params << "CRL=2"
       params << "SecurityCommunity=3"
       logInfoMsg "Starting handoff at : #{url} params #{params}" if $VerboseDebugging
       response =  SRIWeb.instance.postHtml url, params
     end

   end
  end #module Actions
end # module Cougaar
