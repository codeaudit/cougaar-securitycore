#!/usr/bin/ruby

require "security/lib/policy_util.rb"
require "security/lib/policyGenerator/commPolicy.rb"
require 'security/lib/web'


module Cougaar
  module Actions
    class GeneratePoliciesAction < Cougaar::Action
      def initialize(run)
	super(run)
        @run = run
        @staging = File.join(CIP, "workspace", "URPolicies")
        @debug=false
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
        debug"#{output}"
      end

      def commitPolicies(precompiled, wait)
        pws=[]
        @run.society.each_enclave do |enclave|
          if wait then
            pws.push(PolicyWaiter.new(@run, getEnclaveNode(enclave)))
          end
          Thread.fork do
            begin 
              file = "#{policyFileName()}-#{enclave}"
              host, port, manager = getPolicyManager(enclave)
              debug "for enclave found #{host}, #{port}, #{manager}"
              debug "waiting for user manager"
              waitForUserManager(manager)
              debug "user manager ready"
              mutex = getPolicyLock(enclave)
              mutex.synchronize do
                debug "committing policy"
                result = commitPolicy(host, port, manager, 
                                      (isDelta() ? "setpolicies" : "commit") +
                                      (precompiled ? " " : " --dm "),
                                      file,@staging)
                @run.info_message "policy committed for enclave #{enclave}\n"
              end
            rescue => ex
              @run.info_message("Exception in policy code - #{ex} #{ex.backtrace.join("\n")}")
            end
          end
        end
        if wait then
          debug "starting wait"
          pws.each do |pw|
            debug "waiting  for node #{pw}"
            if !pw.wait(300) then
              raise "Policy did not propagate"
            end
            debug "#{pw} wait completed."
          end
        end
      end

      def setDebug(flag)
        @debug = flag
      end
        
      def debug(s)
        if @debug then
          puts("#{s}\n")
        end
      end

      def getEnclaveNode(enclave)
        @run.society.each_enclave_node(enclave) do |node|
          return node.name
        end
      end
    end


    class BuildURPolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run,
                     dbUser     = "society_config",
                     dbHost     = "cougaar-db",
                     dbPassword = "s0c0nfig",
                     db         = "cougaar104")
	super(run)
        @run = run
        @dbUser                = dbUser
        @dbHost                = dbHost
        @dbPassword            = dbPassword
        @db                    = db
      end

      def policyFileName
        File.join("#{@staging}", "policies")
      end

      def isDelta
        false
      end

      def calculatePolicies
        debug"calculating policies"
        `rm -rf #{@staging}`
        Dir.mkdir(@staging)
        p = CommPolicies.new(@run, @dbUser, @dbHost, @dbPassword, @db)
        p.commonDecls()
        p.communityDecls()
        p.allowNameService()
        p.allowSpecialCommunity()
        p.allowRestartCommunityNodesTalk()
        p.allowHealthMonitoring()
        p.allowSecurityManagement()
        p.allowSuperiorSubordinate()
        p.allowInterMnR()
        p.allowServiceProviders()
        p.allowTalkToSelf()
        debug"writing policies #{@staging}"
        p.writePolicies(policyFileName())
        debug "policies written"
      end

      def perform
        calculatePolicies
        compilePolicies
      end
    end

    class InstallURPolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run, wait = false)
	super(run)
        @run = run
        @wait = wait
        #@staging = File.join(CIP, "workspace", "URPolicies")
      end

      def policyFileName
        File.join("#{@staging}", "policies")
      end

      def isDelta
        false
      end

      def perform
        commitPolicies(true, @wait)
      end
    end

    class MigratePolicies < Cougaar::Actions::GeneratePoliciesAction
      def initialize(run, node, enclave)
        super(run)
        @run = run
        @node = node
        @enclave = enclave
        #@staging = File.join(CIP, "workspace", "URPolicies")
      end

      def policyFileName()
        @policyFileName = "#{@staging}/migrationPolicies"
      end

      def isDelta()
        false
      end

      def calculatePolicies
        `rm -rf #{@staging}`
        Dir.mkdir(@staging)
        @run.society.each_enclave do |enclave|
          File.open("#{policyFileName()}-#{enclave}", "w+") do |file|
            debug("writing file #{file}")
            file.write("PolicyPrefix=%MigrationPolicy\n\n")
            file.write("Policy AllowCommunication-#{enclave} = [\n")
            file.write("\tMessageAuthTemplate\n")
            file.write("\tAllow messages from members of $Actor.owl#Agent\n")
            file.write("\tto members of $Actor.owl#Agent\n")
            file.write("]\n")
          end
        end
      end

      def perform
        calculatePolicies
        commitPolicies(false, true)
      end
    end


    class MoveNodeGuard < Cougaar::Action
      def initialize(run, node, enclave)
        super(run)
        @run = run
        @node = node
        @enclave = enclave
      end

      def perform()
        web = SRIWeb.new()
        @nodeagent = getAgentByName(@node)
        web.getHtml(@nodeagent.uri + "/changePolicyManager?" +
                                   getPolicyAgent(@enclave).name + ":" +
                                   getPolicyDomain(@enclave))
      end

      def getPolicyAgent(enclave)
        policyAgent = nil
        @run.society.each_enclave_agent(enclave) do |agent|
          agent.each_facet(:role) do |facet|
            if facet[:role] == $facetPolicyManagerAgent then
              policyAgent = agent
            end
          end
        end
        policyAgent
      end
      
      def getPolicyDomain(enclave)
        enclave.capitalize + "Domain"
      end

      def getAgentByName(aname)
        @run.society.each_agent(true) do |agent|
          if agent.name == aname then
            return agent
          end
        end
        nil
      end
    end


  end
end
