
require 'security/lib/path_utility'

module Cougaar
   module Actions
      class BuildConfigJarFiles < Cougaar::Action
        def perform
          cip = ENV['COUGAAR_INSTALL_PATH']
          packageAndSignJarFile("#{cip}/configs/common", "config_common.jar")
          packageAndSignJarFile("#{cip}/planning/data/common", "config_planning.jar")
          packageAndSignJarFile("#{cip}/configs/glmtrans", "config_glmtrans.jar")
          packageAndSignJarFile("#{cip}/core/configs/common", "core_config_common.jar")
        end
        def packageAndSignJarFile(directory, fileName)
          #puts "Packaging and signing #{directory}/#{fileName}  with all files under #{directory}"

          begin
            File.delete("#{directory}/#{fileName}")
          rescue => detail
            #puts detail.message
          end
          # do not include communities.xml file, as it is generated separately
          files = []
          Dir.foreach(directory) do |entry|
            if entry != "communities.xml" && entry != '.' && entry != '..' && entry != 'alpreg.ini'
              f = "#{directory}/#{entry}"
              files << "#{PathUtility.fixPath(f)}"
            end
          end
          files = files.join(" ")
          p1 = "#{directory}/#{fileName}"
          cmd = "jar cf #{PathUtility.fixPath(p1)} #{files}"
          #puts "Building config files: #{cmd}"
          system(cmd)
          cip = ENV['COUGAAR_INSTALL_PATH']
          signingKeystore="#{cip}/operator/security/signingCA_keystore"
          f1 = "#{directory}/#{fileName}"
          cmd = "jarsigner -keystore #{PathUtility.fixPath(signingKeystore)} -storepass keystore #{PathUtility.fixPath(f1)} privileged"
          #puts cmd
          system(cmd)
          #File.rename(fileName, "#{directory}

        end

      end # PrintSummary
   end
end

