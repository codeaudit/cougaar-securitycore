require 'security/lib/policy_util'

# CIP is defined in policy_util

module Cougaar
   module Actions 
      class WaitForUserManagerReady < Cougaar::Action
        def perform
          run.society.each_enclave { |enclave|
            ::Cougaar.logger.info "Waiting for user manager in #{enclave}"
            host, port, manager = getPolicyManager(enclave)
            waitForUserManager(manager)
          }
        end
      end
      class InitDM < Cougaar::Action
        def perform
          run.society.each_enclave { |enclave|
            ::Cougaar.logger.info "Publishing conditional policy to #{enclave} policy domain manager"
            bootPoliciesLoaded(enclave)
          }
        end
      end # InitDM
   end # Actions
end # Cougaar
