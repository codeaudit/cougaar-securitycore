##
#  <copyright>
#  Copyright 2002 System/Technology Devlopment Corp.
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

require "socket"

module Cougaar

  module States
    class AnalysisServiceVerified < Cougaar::NOOPState
      DOCUMENTATION = Cougaar.document {
        @description = "Indicates that the analysi service was successfully connected to."
      }
    end
  end
  
  module Actions

    class VerifyAnalysisService < Cougaar::Action
      RESULTANT_STATE = 'AnalysisServiceVerified'
      DOCUMENTATION = Cougaar.document {
        @description = "Verifies that the supplied host is running the ACME Service and has the Analysis plugin enabled."
        @parameters = [
          {:host => "required, The host running the ACME Service and Analysis plugin."}
        ]
        @example = "do_action 'VerifyAnalysisService', 'sb042'"
      }
      def initialize(run, jabber_host=nil, analysis_host=nil)
        super(run)
        @jabber_host = jabber_host
        @host = analysis_host
      end
      def perform
        analysis = ::UltraLog::Analysis.from_run(@run, @jabber_host, @host)
        result = analysis.test
        if result =~ /ERROR SENDING/ || result =~ /Unregistered command/
          Cougaar.logger.error "Could not find  Analysis Service on host #{@host}\n#{result}, will not do automated analysis."
          @run['AnalysisServiceVerified'] = false
          #raise "Could not find  Analysis Service on host #{@host}\n Error: #{result}"
        #else
        #  @run['analysis'] = analysis
        end
      end
    end
    
  end
end

module UltraLog

  class Analysis
    TIMEOUT = (60*3) #60 seconds * number of minutes
    
    attr_accessor :run, :analysis_host, :jabber_host
  
    def initialize(run, jabber_host, analysis_host)
      @run = run
      @analysis_host = analysis_host
      @jabber_host = jabber_host
    end
    
    def self.from_run(run, jabber_host=nil, analysis_host=nil)
      unless analysis_host
        analysis_host = run.society.get_service_host("analysis").host_name
      end
      unless jabber_host
        jabber_host = run.society.get_service_host("jabber").host_name
      end
      Analysis.new(run, jabber_host, analysis_host)
    end
  
    def test
      send_command('TestAnalysis', TIMEOUT)
    end
    
    def transfer_data(archive_file, base_name='base', polaris_id=nil, host=nil)
      params = {}
      if ( host == nil )
        params["host"] = Socket.gethostname
      else
        params["host"] = host
      end
      params["expt_name"] = @run.name
      params["run_id"] = @run['cnc_id']
      params["path"] = archive_file
      params["type"] = @run['type']
      params["baseline_name"] = base_name
      params["polaris_id"] = polaris_id if polaris_id != nil

      send_command('TransferData', TIMEOUT, params)
    end

    def create_baseline(base_name='base',polaris_id=nil)
      params = {}
      params["type"] = @run['type']
      params["polaris_id"] = polaris_id if polaris_id != nil
      params["baseline_name"] = base_name

      send_command('AnalyzeSMOP', TIMEOUT, params)
    end

    def analyze_run(base_name='base', polaris_id=nil)
        params = {}
        params["type"] = @run['type']
        params["baseline_name"] = base_name
        params["polaris_id"] = polaris_id if polaris_id != nil
        params["run_id"] = @run['cnc_id']

        send_command('AnalyzeSMOP', TIMEOUT, params)
    end

    private
    
    def send_command(command, timeout=300, params=nil)
      param_str = ""
      if ( params != nil )
        params.each {|key, value| param_str += "#{key}=#{value} " }
        param_str.chomp!(" ")
      end

      begin
        from_jid = "acme_console@#{@jabber_host}/archiver"
        session = Jabber::Session.bind_digest(from_jid, "c0ns0le")
        to_jid = "#{@analysis_host}@#{@jabber_host}/acme"
        message="command[#{command}]#{param_str}"
        @run.info_message "Sending Analysis Command: #{message}"
        
        reply =  session.new_message(to_jid).set_body(message).request(timeout)
        session.close
        if reply.nil?
          @run.error_message "ERROR SENDING: command[#{command}]#{param_str}" 
          #raise "Analysis service timeout or failed connection."
        else
          @run.info_message "Result: #{reply.body}"
        end
        return reply.body
      rescue
        @run.error_message "Error sending analysis command to @jabber_host\n#{$!}\n#{$!.backtrace}"
      end
    end
    
  end
end
