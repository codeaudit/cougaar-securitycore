
require 'security/lib/misc.rb'

module Cougaar
  module Actions
    class InsertPersistenceManagerReadyListener < Cougaar::Action
     
      def initialize(run, persistenceManagerCount=2)
        super(run)
        @run = run
        @persistenceManagerCount = persistenceManagerCount
      end	
      
      def perform
        @run['PersistenceManagerReady'] = false
        @persistenceMgrHash = Hash.new()
        @run.society.each_node do |node|
          @persistenceMgrHash[node.name] = []
          @run.info_message("Adding node to Map -->#{node.name}")  if $VerboseDebugging
        end
        @listener = 
          @run.comms.on_cougaar_event do |event|
            eventCall(event)
        end
      end

      def eventCall(event)
        regexp = /PersistenceManager (.*) PM=(.*) Node=(.*)/
        match = regexp.match(event.data)
        if (match != nil) then
          action = match.to_a[1]
          pm     = match.to_a[2]
          node   = match.to_a[3]
          pms    = @persistenceMgrHash[node]
          if pms == nil then 
           @run.info_message("PersistenceManagerReady Script: received info from node that is not in the society configuration (" + node + ")")
            return
          end
          if (action == "ADD" && !pms.include?(pm)) then
            #puts "Adding PM #{pm} for node  #{node} " 
            #logInfoMessage("Adding PM #{pm}" )
            @run.info_message("Adding PM #{pm} for node #{node}" )  if $VerboseDebugging 
            pms.push(pm)
          elsif (action == "DELETE") then 
             puts "delete PM #{pm}"
            pms.delete(pm)
          end
          if allPersistenceManagersReported then
            @run['PersistenceManagerReady'] = true
            @run.comms.remove_on_cougaar_event(@listener)
            @run.info_message(" Persistance manager ready ")
          end
        end
      end

 
      def allPersistenceManagersReported
        @run.society.each_node do |node|
          #puts "Checking Node #{node.name}"
          if (@persistenceMgrHash[node.name].length != @persistenceManagerCount) then
            @run.info_message("did not find PM for Node  #{node.name}") if $VerboseDebugging
            return false
          end
        end         
        return true
      end
    end
  end
end #Cougaar

module Cougaar
   module States
     class PersistenceManagerReadyWatcher < Cougaar::State

       def initialize(run, timeout=nil, &block)
         super(run, timeout, &block)
         @run = run
       end

      def process
        while (!@run['PersistenceManagerReady'])
          sleep 10.seconds
        end 
      end  
           
    end # PersistenceManagerReady
 end # module States
end #Cougaar
