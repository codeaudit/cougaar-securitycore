require "security/attack/policy"

$ExperimentName = 'Security-3a1'
$ExperimentClass = 'Security3a1Experiment'

class Security3a1Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-3a1'
    @stresses = [ NoAttackMessage ]
  end
end

