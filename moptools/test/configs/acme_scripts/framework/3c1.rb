require "security/attack/message"

$ExperimentName = 'Security-3c1'
$ExperimentClass = 'Security3c1Experiment'

class Security3c1Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-3c1'
    @stresses = [ RequireSSL ]
  end
end

