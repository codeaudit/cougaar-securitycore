#!/usr/bin/ruby

module Cougaar
  module Actions
    class InstallURPolicies < Cougaar::Action
      def initialize(run)
        @run = run
        @staging = File.join(CIP, "workspace", "URPolicies")
        @policyFileName = "policies-"
        @debug = false
      end

      def perform
        calculatePolicies
        compilePolicies(policies)
        commitPolicies
      end

      def calculatePolicies
        debug("calculating policies")
        Dir.mkdir(@staging)
        p = CommPolicies.new(run)
        p.commonDecls()
        p.allowNameService()
        p.allowSpecialCommunity()
        p.allowSecurityManagement()
        p.allowSuperiorSubordinate()
        p.allowInterMnR()
        p.allowServiceProviders()
        p.allowTalkToSelf()
        debug("writing policies"
        p.writePolicies(@staging)
        debug("policies written")
      end

      def compilePolicies
        file = File.join(@staging, 
                         "#{@policiesFileName}#{CommPolicy.@@allEnclaves}")
                        
        output = policyUtil("--maxReasoningDepth 150 build #{file})
        debug(output)
      end

      def commitPolicies
        @run.society.each_enclave do |enclave|
          file = File.join(@staging, 
                           "#{@policiesFileName}#{CommPolicy.@@allEnclaves}")
          host, port, manager = getPolicyManager(enclave)
          debug("for enclave found #{host}, #{port}, #{manager}")
          debug("waiting for user manager")
          waitForUserManager(manager)
          debug("user manager ready")
          mutex = getPolicyLock(enclave)
          mutex.synchronize do
            debug("committing policy")
            result = commitPolicy(host, port, manager, "commit", file)
            debug("policy committed")
          end
        end
      end

    end
  end
end