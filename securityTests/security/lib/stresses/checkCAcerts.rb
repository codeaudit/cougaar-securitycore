class CheckCACerts < SecurityStressFramework
   def initialize(run)
     super(run)
   end

   def postLoadSociety
      @caDomains = CaDomains.instance
      @caDomains.ensureExpectedEntities
   end

   def postConditionalNextOPlanStage
      @caDomains = CaDomains.instance
      # Give the agents time to retrieve their certificates
      sleep 2.minutes unless $WasRunning
      logInfoMsg "validating CA domain entities ..."
      @caDomains.validateDomainEntities
      @caDomains.printIt
      printSummary
   end
end
