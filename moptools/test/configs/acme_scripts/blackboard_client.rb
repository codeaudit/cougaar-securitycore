##
#  <copyright>
#  Copyright 2003 Cougaar Software, Inc.
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

module UltraLog
  class GLSClient
    attr_reader :oplan_name, :oplan_id, :c0_date
    
    def can_send_oplan?
      @can_send_oplan
    end
    
    def gls_connected?
      @gls_connected
    end
    
    def close
      begin
        @gls_connection.finish
        @gls_thread.kill if @gls_thread
      rescue
        Cougaar.logger.error "Error shutting down gls connection: #{$!}"
      end
    end
    
    def initialize(run)
      @run = run
      @gls_connected = false
      @can_send_oplan = false
      @oplan_name = nil
      @oplan_id = nil
      @c0_date=nil
      
      @gls_connection = Net::HTTP.new(@run.society.agents['NCA'].node.host.host_name, @run.society.cougaar_port)
      @gls_thread = Thread.new do
        begin
          req = Net::HTTP::Get.new("/$NCA/glsreply?command=connect")
          Cougaar::Communications::HTTP.authenticate_request(req)
          @gls_connection.request(req) do |resp|
            resp.read_body do |data|
              case data.strip
              when /^<oplan name=.* id=[0-9A-F]*>/
                match = /^<oplan name=(.*) id=([0-9A-F]*)>/.match(data)
                @oplan_name = match[1]
                @oplan_id = match[2]
                @gls_connected = true
              when /^<oplan name=.* id=[0-9A-F]* c0_date=.*>/
                match = /^<oplan name=(.*) id=([0-9A-F]*) c0_date=(.*)>/.match(data)
                @oplan_name = match[1]
                @oplan_id = match[2]
                @c0_date = match[3]
                @gls_connected = true
              when /^<GLS .*>/
                @can_send_oplan = true
              end
            end
          end
        rescue
          Cougaar.logger.error $!
          Cougaar.logger.error $!.backtrace.join("\n")
          Cougaar.logger.info "GLS Connection Closed"
        end
      end
    end
  end
end

module Cougaar  
  module States
  
    class OPlanReady < Cougaar::State
      DEFAULT_TIMEOUT = 30.minutes
      PRIOR_STATES = ["SocietyRunning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for the OPlan ready Cougaar Event."
        @parameters = [
          {:timeout => "default=nil, Amount of time to wait in seconds."},
          {:block => "The timeout handler (unhandled: StopSociety, StopCommunications"}
        ]
        @example = "
          wait_for 'OPlanReady', 2.hours do
            puts 'Did not get OPlanReady!!!'
            do_action 'StopSociety'
            do_action 'StopCommunications'
          end
        "
      }
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end
      
      def process
        loop = true
        while loop
          event = @run.get_next_event
#puts "IN OPlanReady: event is " + event.to_s
          if event.event_type=="STATUS" && event.cluster_identifier=="NCA" && event.component=="OPlanDetector"
            loop = false
          end
        end
#puts "IN OPlanReady: exited loop"
        gls_client = ::UltraLog::GLSClient.new(run)
        @run['gls_client'] = gls_client
        until gls_client.can_send_oplan?
          sleep 2
        end
      end
      
      def unhandled_timeout
        @run.do_action "StopSociety" 
        @run.do_action "StopCommunications"
      end
    end
    
    class GLSReady < Cougaar::State
      DEFAULT_TIMEOUT = 30.minutes
      PRIOR_STATES = ["OPlanSent"]
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for the GLS ready Cougaar Event."
        @parameters = [
          {:timeout => "default=nil, Amount of time to wait in seconds."},
          {:block => "The timeout handler (unhandled: StopSociety, StopCommunications)"}
        ]
        @example = "
          wait_for 'GLSReady', 5.minutes do
            puts 'Did not get GLSReady!!!'
            do_action 'StopSociety'
            do_action 'StopCommunications'
          end
        "
      }
      
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end
      
      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.event_type=="STATUS" && event.cluster_identifier=="5-CORPS" && event.component=="OPlanDetector"
            loop = false
          end
        end
        gls_client = @run['gls_client']
        until gls_client.gls_connected?
          sleep 2
        end
      end
      
      def unhandled_timeout
        @run.do_action "StopSociety"
        @run.do_action "StopCommunications"
      end
    end
    
    class PlanningComplete < Cougaar::State
      DEFAULT_TIMEOUT = 60.minutes
      PRIOR_STATES = ["SocietyPlanning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for the Planning Complete Cougaar Event."
        @parameters = [
          {:timeout => "default=nil, Amount of time to wait in seconds."},
          {:block => "The timeout handler (unhandled: StopSociety, StopCommunications)"}
        ]
        @example = "
          wait_for 'PlanningComplete', 2.hours do
            puts 'Did not get Planning Complete!!!'
            do_action 'StopSociety'
            do_action 'StopCommunications'
          end
        "
      }
      
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end
      
      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.data.include?("Planning Complete")
            loop = false
          end
        end
      end
      
      def unhandled_timeout
        @run.do_action "StopSociety"
        @run.do_action "StopCommunications"
      end
    end

    class RecoverySuccess < Cougaar::State
      DEFAULT_TIMEOUT = 2.minutes
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for Persistent Manager replies with decrypted key."
      }
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end

      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.data.include?("Successfully recover.")
            loop = false
          end
        end
      end

    class RehydrationStart < Cougaar::State
      DEFAULT_TIMEOUT = 10.minutes
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for the DataProtection rehydration event."
      }
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end

      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.data.include?("Try to recover from Persistence Manager.")
            loop = false
          end
        end
      end

      def unhandled_timeout
        @run.do_action "StopSociety"
        @run.do_action "StopCommunications"
      end
    end
    
    class PlanningActive < Cougaar::State
      DEFAULT_TIMEOUT = 60.minutes
      PRIOR_STATES = ["PlanningComplete"]
      DOCUMENTATION = Cougaar.document {
        @description = "Waits for the Planning Active Cougaar Event."
        @parameters = [
          {:timeout => "default=nil, Amount of time to wait in seconds."},
          {:block => "The timeout handler (unhandled: StopSociety, StopCommunications)"}
        ]
        @example = "
          wait_for 'PlanningActive', 10.minutes do
            puts 'Did not get Planning Active!!!'
            do_action 'StopSociety'
            do_action 'StopCommunications'
          end
        "
      }
      
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
      end
      
      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.data.include?("Planning Active")
            loop = false
          end
        end
      end
      
      def unhandled_timeout
        @run.do_action "StopSociety"
        @run.do_action "StopCommunications"
      end
    end
    
    class OPlanSent < Cougaar::NOOPState
      DOCUMENTATION = Cougaar.document {
        @description = "Indicates that the OPlan was sent."
      }
    end
   
    class CheckRevoked < Cougaar::State
      DEFAULT_TIMEOUT = 20.minutes
      DOCUMENTATION = Cougaar.document {
        "Revoke user/agent/node/CA, check response."
        @parameters: [
          {:type => "type of revocation: user/agent/node/CA."},
          {:timeout => "default is nil, Amount of time in seconds."},
          {:block => "The timeout handler {unhandled: StopSociety, StopCommunications."}
        ]
      def initialize(run, type, timeout=nil, &block)
        super(run, timeout, &block)
      end

      def process
        loop = true
        while loop
          event = @run.get_next_event
          if event.data.include?()
            loop = false
          end
        end
      end

      def unhandled_timeout
        @run.do_action "StopSociety"
        @run.do_action "StopCommunications"
      end

    end
 
    class SocietyPlanning < Cougaar::NOOPState
      DOCUMENTATION = Cougaar.document {
        @description = "Indicates that the society is planning."
      }
    end
      
  end
  
  module Actions
 
    class CertificateRevocation < Cougaar::Action
      DOCUMENTATION = Cougaar.document {
        @description = "Revokes a certificate from CA given certificate DN."
        @example = "do_action 'CertificateRevocation' 'FWD-A' 'node'"
      }
      def initialize(run, caAgent, name)
        super(run)
      end
      def perform
        begin
          node = @run.society.agents[caAgent].node
          # role can be obtained from node paramter
          role = getParameter(node, "org.cougaar.core.security.role", 'asmt')
          className = "org.cougaar.core.security.certauthority.ConfigPlugin"
          # cadn, cert attrib, and port can be obtained from ca node component
          # ConfigPlugin's arguments
          cadn = getComponentArgument(node, className)[0]
          revokename = name + cadn[cadn.index(',')..cadn.length]
          port = getComponentArgument(node, className)[2]
          index = port.index(caAgent+':')
          if index == -1
            port = @run.society.cougaar_port
          else
            endindex = port.rindex(':')
            port = port[index + caAgent.length + 1..endindex]
          end
         
          # post http request to ca  
          result = Cougaar::Communications::HTTP.post("http://#{@run.society.agents[#{caAgent}].node.host.host_name}:#{port}/#{caAgent}/revoke", "distinguishedName=#{revokename}&role=#{role}&cadn=#{cadn}")
          raise_failure "Error revoking cert #{revname}" unless result

          # analyst result, should contain success string
          if result.index('successful')
            raise_failure "Error revoking cert #{revname}" 
        end
      end

      # get parameter from node given param name
      def getParameter(node, paramName, default)
        found = nil
        for node.each_parameter do |p|
          found = p if p[2, paramName.length] == paramName
        end
        if found
          return found[2+paramName.length+1..-1]

        puts "No parameter found for #{paramName} on #{node.name}"
        return default
      end

      # get node component argument 
      def getComponentArgument(node, className) 
        found = nil
        for node.each_component do |comp|
          found = comp if comp.classname == className
        end
        if found
          return comp.arguments
        puts "No component with #{className} found on {#node.name}"
        return []
      end
    end
 
    class RehydrateSociety < Cougaar::Action
      PRIOR_STATES = ["SocietyRunning"]
      RESULTANT_STATE = "SocietyPlanning"
      DOCUMENTATION = Cougaar.document {
        @description = "This action is used in place of OPlan/GLS actions if you start a society from a persistent state."
        @example = "do_action 'RehydrateSociety'"
      }
      def perform
      end
    end
    
    class SendOPlan < Cougaar::Action
      PRIOR_STATES = ["OPlanReady"]
      RESULTANT_STATE = "OPlanSent"
      DOCUMENTATION = Cougaar.document {
        @description = "Sends the OPlan to the glsinit servlet."
        @example = "do_action 'SendOPlan'"
      }
      def perform
        begin
          result = Cougaar::Communications::HTTP.get("http://#{@run.society.agents['NCA'].node.host.host_name}:#{@run.society.cougaar_port}/$NCA/glsinit?command=sendoplan")
          raise_failure "Error sending OPlan" unless result
        rescue
          raise_failure "Could not send OPlan", $!
        end
      end
    end
    
    class PublishGLSRoot < Cougaar::Action
      PRIOR_STATES = ["GLSReady"]
      RESULTANT_STATE = "SocietyPlanning"
      DOCUMENTATION = Cougaar.document {
        @description = "Publishes the GLS root task to the glsinit servlet."
        @example = "do_action 'PublishGLSRoot'"
      }
      def perform
        gls_client = @run['gls_client']
        begin
          host_uri = "http://#{@run.society.agents['NCA'].node.host.host_name}:#{@run.society.cougaar_port}"
          if gls_client.c0_date
            result = Cougaar::Communications::HTTP.get("#{host_uri}/$NCA/glsinit?command=publishgls&oplanID=#{gls_client.oplan_id}&c0_date=#{gls_client.c0_date}")
          else
            result = Cougaar::Communications::HTTP.get("#{host_uri}/$NCA/glsinit?command=publishgls&oplanID=#{gls_client.oplan_id}")
          end
          raise_failure "Error publishing OPlan" unless result
        rescue
          raise_failure "Could not publish OPlan", $!
        ensure
          gls_client.close
        end
      end
    end
  end
end
