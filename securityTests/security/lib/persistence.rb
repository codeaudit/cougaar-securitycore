
require 'security/lib/misc.rb'

module Cougaar
  module Actions
    class InsertPersistenceManagerReadyListener < Cougaar::Action
     
      def initialize(run)
        super(run)
        @run = run
        @persistenceManagerCount = 0
        #$VerboseDebugging =true
       
      end	
      
      def perform
        @run['PersistenceManagerReady'] = false
        @persistenceMgrHash = Hash.new()
        @persistenceEnclaveHash = Hash.new()
        @run.society.each_node do |node|
          @run.info_message("Adding node to Map -->#{node.name}")  if $VerboseDebugging
          @persistenceMgrHash[node.name] = []
          if  @persistenceEnclaveHash[node.enclave] == nil
            @persistenceEnclaveHash[node.enclave] = 0
          end
          node.each_facet(:role) do |facet|
            if facet[:role] == $facetManagement ||
               facet[:role] == 'RedundantPersistenceManager'
               @persistenceEnclaveHash[node.enclave] = @persistenceEnclaveHash[node.enclave]+1
                           
            end
          end
        end
        @persistenceEnclaveHash.each_value{ |value|
          @persistenceManagerCount = value
          break
        }
         @run.info_message("setting persitence manager count to: #{@persistenceManagerCount}")
        if @run.comms == nil
           @run.info_message("Warning Unable to complete script Persitence Manager ready run.comms is nil")
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
