#!/usr/bin/ruby

require 'cougaar/communities'
require 'ultralog/enclaves'
require 'security/actions/buildPolicies.rb'
require 'security/lib/jar_util'
require 'security/lib/policy_util'
require 'security/lib/path_utility'
require 'security/lib/common_security_rules'
require 'tmpdir'


module Cougaar
  module Actions
    class BuildCoordinatorPolicies < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end

      def perform
        init()
        constructPolicies()
        compilePolicies()
        packageAndSignJar()
        deleteStagingDir()
      end

      def init
        @cip = ENV['COUGAAR_INSTALL_PATH']
        @stagingdir = "#{CIP}/workspace/BootPolicies-#{rand(1000000)}"
        @highPolicy = "OwlCoordinatorHighPolicy"
        @lowPolicy  = "OwlCoordinatorLowPolicy"
        Dir.mkdir(@stagingdir)
      end

      def compilePolicies
        policyUtil("--maxReasoningDepth 150 --useConfig build OwlBootPolicyList", nil, @stagingdir)
        policyUtil("--maxReasoningDepth 150  build #{@lowPolicy}", nil, @stagingdir)
        policyUtil("--maxReasoningDepth 150  build #{@highPolicy}", nil, @stagingdir)
      end # def compilePolicies

      def packageAndSignJar
        jarFile="#{@cip}/configs/security/coordinatorpolicies.jar"
        signingKeystore="#{@cip}/operator/security/signingCA_keystore"
        begin 
          File.delete(jarFile)
        rescue
          # its ok - problems on the next one aren't.
        end
        result = `cd #{PathUtility.fixPath(@stagingdir)} && jar cf #{PathUtility.fixPath(jarFile)} .`
         #puts "result of jar = #{result}"
        result = `jarsigner -keystore #{PathUtility.fixPath(signingKeystore)} -storepass keystore #{PathUtility.fixPath(jarFile)} privileged`
         #puts "result of jarsigner = #{result}"
      end # def packageAndSignJar


      def deleteStagingDir
        `rm -rf #{@stagingdir}`
      end # def deleteStagingDir

      def constructPolicies
        File.open(File.join(@stagingdir, @highPolicy),
                  File::CREAT|File::WRONLY) do |file|
          file.write <<-EndOfHighPolicy
PolicyPrefix=%Coordinator

Delete EncryptCommunication

Policy HighEncryptCommunication = [ 
  MessageEncryptionTemplate
  Require NSAApprovedProtection on all messages from members of 
  $Actor.owl#Agent to members of $Actor.owl#Agent
]
          EndOfHighPolicy
        end
        File.open(File.join(@stagingdir, @lowPolicy),
                  File::CREAT|File::WRONLY) do |file|
          file.puts("PolicyPrefix=%Coordinator")
          file.puts("AgentGroup \"PolicyManagers\" = \{\"#{getPolicyManagers().join("\",\n\t\"")}\"\}")
          file.write <<-EndOfLowPolicies
Policy LowEncryptCommunication = [ 
  MessageEncryptionTemplate
  Require SecretProtection on all messages from members of the
  complement of $AgentsInGroup#PolicyManagers to members of
  $Actor.owl#Agent 
]

Policy LowPolicyManagerEncryptCommunication = [
  MessageEncryptionTemplate
  Require NSAApprovedProtection on all messages from members of 
  $AgentsInGroup#PolicyManagers to members of $Actor.owl#Agent 
]
          EndOfLowPolicies
        end
      end

      def getPolicyManagers()
        pms = []
        @run.society.each_agent do |agent|
          agent.each_facet(:role) do |facet|
            if facet[:role] ==  $facetPolicyManagerAgent then
              pms.push(agent.name)
            end
          end
        end
        pms
      end


    end # class BuildPolicies
  end # module Actions
end # module Cougaar
