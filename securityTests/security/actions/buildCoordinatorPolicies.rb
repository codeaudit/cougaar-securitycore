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
        compilePolicies()
        packageAndSignJar()
        deleteStagingDir()
      end

      def init
        @cip = ENV['COUGAAR_INSTALL_PATH']
        @stagingdir = "#{CIP}/workspace/BootPolicies-#{rand(1000000)}"
        Dir.mkdir(@stagingdir)
      end

      def compilePolicies
        policyUtil("--maxReasoningDepth 150 --useConfig build OwlBootPolicyList", nil, @stagingdir)
        policyUtil("--maxReasoningDepth 150 --useConfig build OwlCoordinatorLowPolicy", nil, @stagingdir)
        policyUtil("--maxReasoningDepth 150 --useConfig build OwlCoordinatorHighPolicy", nil, @stagingdir)
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

    end # class BuildPolicies
  end # module Actions
end # module Cougaar
