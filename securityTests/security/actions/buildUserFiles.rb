#!/usr/bin/ruby

require 'cougaar/communities'
require 'ultralog/enclaves'
require 'security/lib/jar_util'
require 'security/lib/path_utility'
require 'security/lib/common_security_rules'

module Cougaar
  module Actions
    class BuildUserFiles < Cougaar::Action
      def perform
        init()
        buildUserFiles()
        packageAndSignJar()
        deleteStagingDir()
      end

      def init
        @cip = ENV['COUGAAR_INSTALL_PATH']
        @stagingdir = "/tmp/UserFiles-#{rand(1000000)}"
        Dir.mkdir(@stagingdir)
      end

      def buildUserFiles
        @domains = []
        run.society.communities.each do |community|
           community.each_attribute do |key, value|
             #puts "===== #{community.name} #{key} #{value}"
             if key == 'CommunityType' && value == 'User'
               @domains.push(community.name)
             end
           end
        end
        @domains.each do |domain|
          #puts "Generating User file for #{domain}"
          cmdLine = "java -Dorg.cougaar.config.path=#{@cip}/configs/security\\;#{@cip}/configs/common"
          cmdLine += " -Dorg.cougaar.install.path=#{@cip} "
          cmdLine += " -Dorg.cougaar.util.ConfigFinder.ClassName=org.cougaar.util.jar.JarConfigFinder"
          cmdLine += " -Xbootclasspath/a:#{@cip}/lib/bootstrap.jar "
          cmdLine += " org.cougaar.bootstrap.Bootstrapper "
          cmdLine += " org.cougaar.core.security.acl.user.UserFileParser -d #{domain}"
          #puts cmdLine
          `cd #{@stagingdir} && #{cmdLine}`
        end
      end # def buildUserFiles

      def packageAndSignJar
        jarFile="#{@cip}/configs/security/userFiles.jar"
        signingKeystore="#{@cip}/operator/security/signingCA_keystore"
        begin
          File.delete(jarFile)
        rescue
          # its ok - problems on the next one aren't.
        end
        result = `cd #{@stagingdir} && jar cf #{jarFile} .`
        # puts "result of jar = #{result}"
        result = `jarsigner -keystore #{PathUtility.fixPath(signingKeystore)} -storepass keystore #{PathUtility.fixPath(jarFile)} privileged`
        # puts "result of jarsigner = #{result}"
      end # def packageAndSignJar

      def deleteStagingDir
        `rm -rf #{@stagingdir}`
      end # def deleteStagingDir

    end
  end
end

