require "security/attack/registration"

$ExperimentName = 'Security-5j102'
$ExperimentClass = 'Security5j102Experiment'

class Security5j102Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-5j102'
    @stresses = [ CountCRLRegistrations ]
  end
end
