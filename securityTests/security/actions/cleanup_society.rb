##
#  <copyright>
#  Copyright 2002 InfoEther, LLC
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

require 'parsedate'

module Cougaar

  module Actions

    class CleanupSociety < Cougaar::Action
      PRIOR_STATES = ["CommunicationsRunning"]
      DOCUMENTATION = Cougaar.document {
        @description = "Stop all Java processes and remove actives stressors on all hosts listed in the society."
        @example = "do_action 'CleanupSociety'"
      }


      def perform
        society = @run.society
        society = Ultralog::OperatorUtils::HostManager.new.load_society unless society

        hosts = []
        society.each_service_host("acme") do |host|
          hosts << host
        end
        hosts.each_parallel do |host|
          @run.info_message "Shutting down acme on #{host}\n" if @debug
          @run.comms.new_message(host).set_body("command[nic]reset").send
          @run.comms.new_message(host).set_body("command[rexec]killall -9 java").request(30)
          # kills don't always work first time, try again to be sure
          @run.comms.new_message(host).set_body("command[rexec]killall -9 java").request(30)
          @run.comms.new_message(host).set_body("command[cpu]0").send()
          @run.comms.new_message(host).set_body("command[shutdown]").send()
        end

        society.each_service_host("operator") do |host|
          @run.info_message "Shutting down acme on #{host}\n" if @debug
          @run.comms.new_message(host).set_body("command[nic]reset").send
          @run.comms.new_message(host).set_body("command[rexec]killall -9 java").request(30)
          # kills don't always work first time, try again to be sure
          @run.comms.new_message(host).set_body("command[rexec]killall -9 java").request(30)
          @run.comms.new_message(host).set_body("command[cpu]0").send()
        end
        @run.info_message "Waiting for ACME services to restart"

        sleep 20 # wait for all acme servers to start back up
      end
    end
  end
end
