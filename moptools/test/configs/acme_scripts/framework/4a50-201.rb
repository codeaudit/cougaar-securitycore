require "security/attack/config"

$ExperimentName = 'Security-4a50201'
$ExperimentClass = 'Security4a50201Experiment'

class Security4a50201Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-4a50201'
    @stresses = [ 
      Security4a50Stress,
      Security4a51Stress, 
      Security4a52Stress,
      Security4a53Stress,
      Security4a201Stress
    ]
  end
end

