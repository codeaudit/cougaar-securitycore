#!/usr/bin/ruby

require "security/lib/policyGenerator/commPolicy.rb"


module Cougaar
  module Actions
    class GeneratePoliciesAction < Cougaar::Action
      def initialize(run)
	super(run)
        @run = run
        @staging = File.join(CIP, "workspace", "URPolicies")
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
        file = policyFileName()+"-AllEnclaves"
        output = policyUtil("--maxReasoningDepth 150 build #{file}", nil,@staging)
        puts"#{output}"
      end

      def commitPolicies
        @run.society.each_enclave do |enclave|
          Thread.fork do
            file = "#{policyFileName()}-#{enclave}"
            host, port, manager = getPolicyManager(enclave)
            puts "for enclave found #{host}, #{port}, #{manager}"
            puts "waiting for user manager"
            waitForUserManager(manager)
            puts "user manager ready"
            mutex = getPolicyLock(enclave)
            mutex.synchronize do
              puts "committing policy"
              result = commitPolicy(host, port, manager, 
                                    isDelta()? "setpolicies" : "commit", file,@staging)
              puts "policy committed for enclave #{enclave}"
            end
          end
        end
      end


    end


    class BuildURPolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run)
	super(run)
        @run = run
        #@staging = File.join(CIP, "workspace", "URPolicies")
        @debug = false
      end

      def policyFileName
        File.join("#{@staging}", "policies")
      end

      def isDelta
        false
      end

      def calculatePolicies
        puts"calculating policies"
        `rm -rf #{@staging}`
        Dir.mkdir(@staging)
        p = CommPolicies.new(@run)
        p.commonDecls()
        p.allowNameService()
        p.allowSpecialCommunity()
        p.allowSecurityManagement()
        p.allowSuperiorSubordinate()
        p.allowInterMnR()
        p.allowServiceProviders()
        p.allowTalkToSelf()
        puts"writing policies #{@staging}"
        p.writePolicies(policyFileName())
        puts "policies written"
      end

      def perform
        calculatePolicies
        compilePolicies
      end

    end

    class InstallURPolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run)
	super(run)
        @run = run
        #@staging = File.join(CIP, "workspace", "URPolicies")
        @debug = false
      end

      def policyFileName
        File.join("#{@staging}", "policies")
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
            puts("#{ex.backtrace.join("\n")}")
          end
        end
      end
    end

    class MigratePolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run, node, enclave)
        super(run)
        @run = run
        @node = node
        @enclave = enclave
        #@staging = File.join(CIP, "workspace", "URPolicies")
        @debug = false
      end

      def policyFileName()
        @policyFileName = "#{@staging}/migrationPolicies"
      end

      def isDelta()
        true
      end

      def calculatePolicies
	puts "calculating policies"
        Dir.mkdir(@staging)
        p = CommPolicies.new(run)
        p.commonDeclsMigrate(@node, @enclave)
        p.allowSecurityManagementMigrate(@enclave)
        puts "writing policies"
        p.writePolicies(@policyFileName)
        puts "policies written"
      end

      def perform
        calculatePolicies
        compilePolicies
        commitPolicies
      end
    end

  end
end
