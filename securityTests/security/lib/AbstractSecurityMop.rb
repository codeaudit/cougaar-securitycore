require 'singleton'
require 'security/lib/security'

class AbstractSecurityMop < SecurityStressFramework
  attr_accessor :date, :runid, :name, :descript, :score, :info, :isCalculationDone, :raw, :summary
  @@halt = false
  def self.getHalt
    return @@halt
  end
  def self.setHalt(haltValue)
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
