class PrintDotsOnCougaarEvents < SecurityStressFramework
   def postStartJabberCommunications
      printDotsOnCougaarEvents(/oplan|gls|idmef|operating/i)
   end
end
