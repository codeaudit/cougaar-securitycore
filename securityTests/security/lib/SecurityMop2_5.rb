require 'security/lib/AbstractSecurityMop'
require 'security/lib/SecurityMop2_4'

class SecurityMop2_5 < AbstractSecurityMop
  include Singleton
  

 # def initialize(run)
 #   super(run)
 #   @name = "2-5"
 #   @descript = "Percentage of all designated user actions that are recorded"
 # end
  
  def initialize()
    #   super(run)
    @name = "2-5"
    @descript = "Percentage of all designated user actions that are recorded"
  end

  def getStressIds()
    return ["SecurityMop2.5"]
  end


  def to_s
    logged = SecurityMop2_4.instance.numActionsLogged
    total = SecurityMop2_4.instance.numLoggableActions
    answer = 100
    answer = logged / total unless total == 0
    return "policy actions: (logged)#{logged}/(total)#{total} = #{answer}"
  end

  def calculationDone
    return SecurityMop2_4.instance.calculationDone
  end

  def calculate
    Thread.fork {
      begin
        totalWaitTime=0
        maxWaitTime = 30.minutes
        sleepTime=60.seconds
        while ((SecurityMop2_4.instance.getPerformDone == false) && (totalWaitTime < maxWaitTime))
          logInfoMsg "Sleeping in Calculate of SecurityMop2.5 . Already slept for #{totalWaitTime}"
          sleep(sleepTime) # sleep
          totalWaitTime += sleepTime
        end
        if((totalWaitTime >= maxWaitTime) && (SecurityMop2_4.instance.getPerformDone == false))
          saveResult(false, "SecurityMop2.5", "Timeout tests incomplete") 
           logInfoMsg "Save results for SecurityMop2.5 Done Result failed "
          return
        elsif (SecurityMop2_4.instance.getPerformDone == true)
          @score = SecurityMop2_4.instance.score5
          logged = SecurityMop2_4.instance.numActionsLogged
          total = SecurityMop2_4.instance.numLoggableActions
          if total == 0
            if @numAccessAttempts == 0
              @summary = "There weren't any access attempts."
            else
              @summary = "There weren't any access attempts which needed to be logged."
            end
          else
            # note: these two values are swapped, but are fixed on the analysis side
            @summary = "There were #{total} servlet access attempts,#{logged} were correct.\n"
          end
          @raw = SecurityMop2_4.instance.raw5
          @info = SecurityMop2_4.instance.html5
          @summary <<"<BR> Score :#{@score}</BR>\n" 
          @summary << "#{@info}"
          success = false
          if (@score == 100.0)
            success = true
          end
          saveResult(success, 'SecurityMop2.5',@summary)
          logInfoMsg "Save results for SecurityMop2.5 Done" 
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
    
