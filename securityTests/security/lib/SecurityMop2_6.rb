require 'security/lib/AbstractSecurityMop'
require 'security/lib/SecurityMop2_4'

class SecurityMop26 < AbstractSecurityMop
  include Singleton
  

  #def initialize(run)
  #  super(run)
  #  @name = "2-6"
  #  @descript = "Percentage of all designated user actions in violation of policy that are recorded as policy violations"
  #end
  
  def initialize()
    #super(run)
    @name = "SecurityMop2.6"

    @descript = "Percentage of all designated user actions in violation of policy that are recorded as policy violations"
  end

  def getStressIds()
    return ["SecurityMop2.6","1A1-1A20","1A2-1A21","1A4-1A23","1A5-1A24","1A51-1A241","1A6-1A25","1A7-1A26","1A8-1A27","1A9-1A28","1A10-1A29"]
  end

  def to_s
    logged = SecurityMop2_4.instance.numPoliciesLogged
    total = SecurityMop2_4.instance.numLoggablePolicies
    answer = 100
    answer = logged / total unless total == 0
    return "policy actions: (logged)#{logged}/(total)#{total} = #{answer}"
  end

  def isCalculationDone
    return SecurityMop2_4.instance.isCalculationDone
  end

  def calculate
    Thread.fork {
      begin
        totalWaitTime=0
        maxWaitTime = 30.minutes
        sleepTime=60.seconds
        while ((SecurityMop2_4.instance.getPerformDone == false) && (totalWaitTime < maxWaitTime))
          logInfoMsg "Sleeping in Calculate of SecurityMop2.6 . Already slept for #{totalWaitTime}"
          sleep(sleepTime) # sleep
          totalWaitTime += sleepTime
        end
        if((totalWaitTime >= maxWaitTime) && (SecurityMop2_4.instance.getPerformDone == false))
          saveResult(false, "SecurityMop2.6", "Timeout tests incomplete") 
            saveAssertion("SecurityMop2.6", "Save results for SecurityMop2.6 Done Result failed ")
          return
        elsif (SecurityMop2_4.instance.getPerformDone == true)
          @score = SecurityMop2_4.instance.score6
          logged = SecurityMop2_4.instance.numPoliciesLogged
          total = SecurityMop2_4.instance.numLoggablePolicies
          if total == 0
            if @numAccessAttempts == 0
              @summary = "There weren't any access attempts."
            else
              @summary = "There weren't any access attempts which needed to be logged."
              
            end
          else
            # note: these two values are swapped, but are fixed on the analysis side
            @summary = "There were #{total} servlet access attempts, #{logged} were correct."
          end
          @raw = SecurityMop2_4.instance.raw6
          @info = SecurityMop2_4.instance.html6
          @summary <<"<BR> Score :#{@score}</BR>\n" 
          @summary << "#{@info}"
          success = false
          if (@score == 100.0)
            success = true
          end
          saveResult(success, 'SecurityMop2.6',@summary)
          saveAssertion("SecurityMop2.6", "Save results for SecurityMop2.6 Done" )
        end
      rescue Exception => e
        puts "error in 2.4 calculate "
        puts "#{e.class}: #{e.message}"
        puts e.backtrace.join("\n")
      end
    }
  end

  def scoreText
    if @summary =~ /^There weren/
      return NoScore
    else
      return @score
    end
  end
end

class SecurityMop2_6 < SecurityMop26
  include Singleton
end
