require 'security/lib/certRevocation'

class SecurityTest < SecurityStressFramework
   def initialize(run)
      super(run)
   end

   def postConditionalStartSociety
     certRevocation = CertRevocation.new
     certRevocation.setAgentExpiration("FwdEnclaveCaManager", "300 d")
   end
end


