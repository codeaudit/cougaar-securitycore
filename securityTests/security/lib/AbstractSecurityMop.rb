require 'singleton'
require 'security/lib/security'

class AbstractSecurityMop < SecurityStressFramework

  attr_accessor :date, :runid, :name, :descript, :score, :info, :calculationDone, :raw, :summary
  def initialize(run)
    super(run)
    @runid = ''
    @calculationDone = false
    @summary = ''
    @info = ''
    @score = 0
    @raw = []
  end
  def setup
    # default is to do nothing
  end
  def perform
    # default is to do nothing
  end
  def shutdown
    # default is to do nothing
  end
  def calculate
    # default is to do nothing
  end
end
