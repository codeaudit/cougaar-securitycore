#!/usr/bin/ruby

require 'cougaar/communities'
require 'ultralog/enclaves'
require 'security/lib/jar_util'
require 'security/lib/path_utility'
require 'security/lib/common_security_rules'
require 'tmpdir'

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
        @stagingdir = "#{Dir::tmpdir}/UserFiles-#{rand(1000000)}"
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
          bootcp = PathUtility.fixPath("#{@cip}/lib/bootstrap.jar")
          cfgPath1 = PathUtility.fixPath("#{@cip}/configs/security")
          cfgPath2 = PathUtility.fixPath("#{@cip}/configs/common")
          if PathUtility::isWindows
            cfgPath = "#{cfgPath1};#{cfgPath2}"
          else
            cfgPath = "#{cfgPath1}\\;#{cfgPath2}"
          end
          cmdLine = "java -Dorg.cougaar.config.path=#{cfgPath}"
          cmdLine += " -Dorg.cougaar.install.path=#{PathUtility.fixPath(@cip)} "
          cmdLine += " -Dorg.cougaar.util.ConfigFinder.ClassName=org.cougaar.util.jar.JarConfigFinder"
          cmdLine += " -Xbootclasspath/a:#{bootcp} "
          cmdLine += " org.cougaar.bootstrap.Bootstrapper "
          cmdLine += " org.cougaar.core.security.acl.user.UserFileParser -d #{domain}"
          #puts cmdLine
          `cd #{PathUtility.fixPath(@stagingdir)} && #{cmdLine}`
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
        cmd = "jar -cf #{PathUtility.fixPath(jarFile)} -C #{PathUtility.fixPath(@stagingdir)} \\."
        #puts "Jar user file: #{cmd}"
        result = system(cmd)
        #puts "result of jar = #{result}"
        result = `jarsigner -keystore #{PathUtility.fixPath(signingKeystore)} -storepass keystore #{PathUtility.fixPath(jarFile)} privileged`
        # puts "result of jarsigner = #{result}"
      end # def packageAndSignJar

      def deleteStagingDir
        #`rm -rf #{@stagingdir}`
      end # def deleteStagingDir

    end
  end
end

