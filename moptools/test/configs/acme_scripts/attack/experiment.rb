require 'security/attack/attackutil.rb'
require 'security/attack/message.rb'
require 'security/attack/policy.rb'
require 'security/attack/registration.rb'

class SecurityGeorgeExperiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-George'
    @stresses = [ CountCrlRegistrations, CountMRRegistrations, RequireSSL ]
  end
end
