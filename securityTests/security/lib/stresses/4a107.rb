require 'security/lib/dataProtection'

class Security4a107Experiment < SecurityStressFramework

   def initialize
      super
   end


   def postLoadSociety
puts "remove data protection"
     @run.society.each_node do |node|
       node.override_parameter("-Dorg.cougaar.core.security.dataprotection", "false")
     end
   end

#   def postConditionalStartSociety
      # Give the agents time to retrieve their certificates
#      sleep 10.minutes #unless $WasRunning
   def postConditionalGLSConnection
# 4A107
      dataProtection = DataProtection.new
      result = (dataProtection.checkDataEncrypted('cougaar') >= 100)
      saveResult(result, "4a107", "no persisted data encrypted if dataprotection is not turned on")
#exit 0

   end


   def printSummary
   end



end

