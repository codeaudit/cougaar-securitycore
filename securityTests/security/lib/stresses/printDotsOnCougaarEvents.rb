class PrintDotsOnCougaarEvents < SecurityStressFramework
   def initialize(run)
     super(run)
   end

   def postStartJabberCommunications
      printDotsOnCougaarEvents(/oplan|gls|idmef|operating/i)
   end
end
