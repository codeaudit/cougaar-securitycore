require 'framework/policy_util'

# CIP is defined in policy_util

module Cougaar
   module Actions 
      class PublishConditionalPolicies < Cougaar::Action
        def perform
          run.society.each_enclave { |enclave|
            ::Cougaar.logger.info "Publishing conditional policy to #{enclave} policy domain manager"
            deltaPolicy(enclave, <<END_POLICY)
PolicyPrefix=%CondPolicy/

Delete CertWriteAuth

Policy CertWriteAuthLow  = [ 
  ServletAuthenticationTemplate
  All users must use Password, PasswordSSL, CertificateSSL
  authentication when accessing the servlet named CAWriteServlet
] when operating mode = LOW

Policy CertWriteAuthHigh  = [ 
  ServletAuthenticationTemplate
  All users must use PasswordSSL, CertificateSSL
  authentication when accessing the servlet named CAWriteServlet
] when operating mode = HIGH

END_POLICY
          }
        end
      end # PublishConditionalPolicies
   end # Actions
end # Cougaar
