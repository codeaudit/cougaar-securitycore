#!/usr/bin/ruby

require "security/lib/policyGenerator/commPolicy.rb"


module Cougaar
  module Actions
    class BuildURPolicies < GeneratePoliciesAction
      def initialize(run)
        @run = run
        @staging = File.join(CIP, "workspace", "URPolicies")
        @debug = false
      end

      def policyFileName
        File.join("#{staging}"), "policies"
      end

      def isDelta
        false
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

      def perform
        calculatePolicies
        compilePolicies
      end
    end

    class InstallURPolicies < GeneratePoliciesAction
      def initialize(run)
        @run = run
        @staging = File.join(CIP, "workspace", "URPolicies")
        @debug = false
      end

      def policyFileName
        File.join("#{staging}"), "policies"
        raise "Abstract Class"
      end

      def isDelta
        false
      end

      def perform
        Thread.fork do
          begin
            commitPolicies
          rescue => ex
            puts("Exception")
            puts("ex.backtrace.join("\n"))
          end
        end
      end
    end

    class MigrationPolicies < GeneratePoliciesAction
      def initialize(run, node, enclave)
        super(run)
        @run = run
        @node = node
        @enclave = enclave
        @staging = File.join(CIP, "workspace", "URPolicies")
        @debug = false
      end

      def policyFileName()
        @policyFileName = "#{@staging}/migrationPolicies"
      end

      def isDelta()
        true
      end

      def calculatePolicies
        debug("calculating policies")
        Dir.mkdir(@staging)
        p = CommPolicies.new(run)
        p.commonDeclsMigrate(@node, @enclave)
        p.allowSecurityManagementMigrate(@enclave)
        debug("writing policies")
        p.writePolicies(@policyFileName)
        debug("policies written")
      end

      def perform
        calculatePolicies
        compilePolicies
        commitPolicies
      end
    end

    class GeneratePoliciesAction < Cougaar:Action
      def initialize(run)
        @run = run
      end
    
      def policyFileName
        raise "Abstract class"
      end

      def isDelta
        raise "AbstractClass"
      end

      def perform
        raise "Abstract Class"
      end

      def compilePolicies
        file = "#{@policiesFileName}-#{CommPolicy.@@allEnclaves}"
                        
        output = policyUtil("--maxReasoningDepth 150 build #{file})
        debug(output)
      end

      def commitPolicies
        @run.society.each_enclave do |enclave|
          file = "#{policyFileName()}-#{enclave}")
          host, port, manager = getPolicyManager(enclave)
          debug("for enclave found #{host}, #{port}, #{manager}")
          debug("waiting for user manager")
          waitForUserManager(manager)
          debug("user manager ready")
          mutex = getPolicyLock(enclave)
          mutex.synchronize do
            debug("committing policy")
            result = commitPolicy(host, port, manager, 
                                  @delta ? "setpolicies" : "commit", file)
            debug("policy committed")
          end
        end
      end


    end
  end
end