#!/usr/bin/ruby


require "security/lib/policy_util.rb"

module Cougaar
  module Actions
    class InstallBootPolicies < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
        @debug = false
      end

      def perform()
        pws=[]
        @run.society.each_enclave do |enclave|
          enclaveNode = nil
          @run.society.each_node do |node|
            if node.host.enclave == enclave
              enclaveNode = node
              break
            end
          end
          pws.push(PolicyWaiter.new(@run, enclaveNode.name))
        end
        @run.society.each_enclave do |enclave|
          Thread.fork do
            begin 
              host, port, manager = getPolicyManager(enclave)
              debug "for enclave found #{host}, #{port}, #{manager}"
              debug "waiting for user manager"
              waitForUserManager(manager)
              debug "user manager ready"
              mutex = getPolicyLock(enclave)
              mutex.synchronize do
                debug "committing policy"
                result = commitPolicy(host, port, manager, 
                                      " --useConfig commit --dm ",
                                      "OwlBootPolicyList")
                debug("Result for enclave #{enclave} = #{result}")
                @run.info_message "policy committed for enclave #{enclave}\n"
              end
            rescue => ex
              @run.info_message("Exception in policy code - #{ex} #{ex.backtrace.join("\n")}")
            end
          end # Thread.fork do
        end # @run.society.each_enclave do |enclave|
        debug "starting wait"
        pws.each do |pw|
          debug "waiting  for node #{pw}"
          if !pw.wait(3000) then
            raise "Policy did not propagate"
          end
          debug "#{pw} wait completed."
        end
      end # def perform

      def debug(s)
        if @debug
          @run.info_message(s)
        end
      end
    end # class InstallBootPolicies
  end # module Actions
end # module Cougaar
