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

require 'assessment/setup'
require 'assessment/cnccalc'
require 'assessment/pertubations'
require 'assessment/stressors'
require 'assessment/network'
require 'assessment/analysis'
require 'assessment/aggagent_queries'
require 'assessment/agent_msg_rate'

require 'uri'
require 'net/http'

module Cougaar
  module Actions
    class FreezeAsmtSociety < Cougaar::Action
=begin
      PRIOR_STATES = ["SocietyRunning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Assessment version of DFreezeSociety society action. Similar to acme action only catches exceptions so that script does not abort."
        @example = "do_action 'FreezeAsmtSociety'"
      }
=end
      def initialize(run, timeout=nil, &block)
        super(run)
        @timeout = timeout
        @timeout = 3600 if @timeout.nil?
        @action = block if block_given?
      end
      def perform
        freezeControl = ::UltraLog::FreezeControl.new(@run.society)
        freezeControl.freeze
        begin
          freezeControl.wait_until_frozen(@timeout)
        rescue
          @run.error_message "Could not freeze society"
        end
        @action.call(freezeControl) if @action
      end
   end
  end
end
