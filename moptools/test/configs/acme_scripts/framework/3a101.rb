require "security/attack/message"

$ExperimentName = 'Security-3a101'
$ExperimentClass = 'Security3a101Experiment'

class Security3a101Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-3a101'
    @stresses = [ Stress3a101 ]
  end
end

