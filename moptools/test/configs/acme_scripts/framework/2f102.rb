require "security/attack/registration"

$ExperimentName = 'Security-2f102'
$ExperimentClass = 'Security2f102Experiment'

class Security2f102Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-2f102'
    @stresses = [ CountMRRegistrations ]
  end
end

