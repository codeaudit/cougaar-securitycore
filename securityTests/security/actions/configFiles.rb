
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
          puts "Packaging and signing #{directory}/#{fileName}  with all files under #{directory}"

          begin
            File.delete("#{directory}/#{fileName}")
          rescue => detail
            #puts detail.message
          end
          # do not include communities.xml file, as it is generated separately
          cmd = "jar cf #{directory}/#{fileName} `ls #{directory}/* | grep -v \"communities.xml\"`"
          #puts cmd
          system(cmd)
          cip = ENV['COUGAAR_INSTALL_PATH']
          signingKeystore="#{cip}/configs/security/bin/signingCA_keystore"
          cmd = "jarsigner -keystore #{signingKeystore} -storepass keystore #{directory}/#{fileName} privileged"
          #puts cmd
          system(cmd)
          #File.rename(fileName, "#{directory}

        end

      end # PrintSummary
   end
end

