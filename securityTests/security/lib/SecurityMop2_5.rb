require 'security/lib/AbstractSecurityMop'
require 'security/lib/SecurityMop2_4'

class SecurityMop2_5 < AbstractSecurityMop
  include Singleton
  
  def initialize(run)
    super(run)
    @name = "2-5"
    @descript = "Percentage of all designated user actions that are recorded"
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
    while !calculationDone do
      sleep 2.seconds
    end
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
      @summary = "There were #{logged} servlet access attempts, #{total} were correct."
    end
    @raw = SecurityMop2_4.instance.raw5
    @info = SecurityMop2_4.instance.html5
  end

  def scoreText
    if @summary =~ /^There weren/
      return NoScore
    else
      return @score
    end
  end
end
    
