require 'singleton'
require 'security/lib/security'

class Object
  def threadPerformAction
    Thread.fork do
      begin
        self.performAction
      rescue Exception => e
        logErrorMsg "Error in #{anObject.class.name}: #{e.class}, #{e.message}"
        logErrorMsg e.backtrace.join("\n")
      end
    end
  end
end


class AbstractSecurityMop < SecurityStressFramework
  attr_accessor :date, :runid, :name, :descript, :score, :info, :isCalculationDone, :raw, :summary, :supportingData

  @@completed = []

  def self.member?(anObject)
    return @@completed.member?(anObject)
  end
  def self.finished(anObject)
    logInfoMsg "AbstractSecurityMop.finished '#{anObject}'" if $VerboseDebugging
    @@completed << anObject
  end
  def self.completed
    return @@completed
  end
  def self.waitForCompletion(completedName, maxTime=30.minutes)
    # returns true if completedName comes in before maxTime
    startTime = Time.now
    sleepTime = 5.seconds
    until @@completed.member?(completedName) do
      logInfoMsg "Waiting for '#{completedName}' to finish" if $VerboseDebugging
      if startTime+maxTime < Time.now
        logInfoMsg "Timeout exceeded waiting for #{completedName}"
        return false
      end
      sleep sleepTime
    end
    logInfoMsg "'#{completedName}' has completed" if $VerboseDebugging
    return true
  end

  @@halt = false
  def self.getHalt
    return @@halt
  end
  def self.setHalt(haltValue)
    logInfoMsg "AbstractSecurityMop.halt" if $VerboseDebugging
    @@halt = haltValue
  end
  def self.halt
    return AbstractSecurityMop.getHalt
  end
  def self.halt=(haltValue)
    AbstractSecurityMop.setHalt(haltValue)
  end
  def halt
    return self.halt
  end
  def halt=(haltValue)
    self.halt = haltValue
  end
  def initialize(run)
    super(run)
    @runid = ''
    @isCalculationDone = false
    @summary = ''
    @info = ''
    @score = 0
    @raw = []
    @supportingData = {}
  end
  def self.instance
    return Cougaar::Actions::Stressors.getStressInstance(self.name, getRun)
  end
  def getStressIds()
    return ["AbstractSecurityMop"]
  end
  def setup
    # default is to do nothing
  end
  def perform
    # default is to do nothing
  end
  def doRunPeriodically
    return false
  end
  def shutdown
    # default is to do nothing
  end
  def calculate
    # default is to do nothing
    # note: this method can return immediately.
    #   things won't continue until its isCalculationDone method
    #   returns true
  end
  def isCalculationDone
    return true
  end
  def postCalculate
    # this method must not return until its calculation is done
    #    i.e., there is no isPostCalculateDone
  end
end

class SecurityMopNil < AbstractSecurityMop
  # a do-nothing security mop. useful as the 0th place holder so that
  # SecurityMop2_1 is in slot [1], SecurityMop2_2 in [2], etc.
end
