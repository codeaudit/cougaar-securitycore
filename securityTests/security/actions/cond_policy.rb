require 'lib/policy_util'

# CIP is defined in policy_util

module Cougaar
   module Actions 
      class PublishConditionalPolicies < Cougaar::Action
        def initialize(run, joinThreads=true, timeout=1.hour)
          super(run)
          @timeout = timeout
          @joinThreads = joinThreads
        end

        def perform
          threads = Hash.new
          @run.society.each_enclave { |enclave|
            begin
              ::Cougaar.logger.info "Publishing conditional policy to #{enclave} policy domain manager"
              thread = Thread.fork {
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
                ::Cougaar.logger.info "Finished publishing conditional policy for #{enclave}"
              }
              threads[enclave]=thread
            rescue => e
              puts e.message;
              puts e.backtrace.join("\n");
            end
          }
          @run['ConditionalPolicyThreads'] = threads
          if (@joinThreads)
            quitTime = Time.now + @timeout
            while (Time.now.to_f < quitTime.to_f)
              finishedThreads = Array.new
              threads.each_pair { |enclave, thread|
                if (!thread.alive?)
                  thread.join
                  finishedThreads << enclave
                end
              }
              finishedThreads.each { |enclave|
                threads.delete(enclave)
              }
              if (threads.size > 0)
                sleep 10.seconds
              else 
                return nil
              end
            end
            # kill the threads -- they wouldn't stop
            threads.each_pair { |enclave, thread|
              ::Cougaar.logger.warn "Could not complete " +
                "PublishConditionalPolicies for enclave #{enclave}"
              thread.kill
            }
          end
        end
      end # PublishConditionalPolicies
   end # Actions

   module States
     class ConditionalPolicies < Cougaar::State
       DEFAULT_TIMEOUT = 45.minutes
       PRIOR_STATES = ["SocietyRunning"]
       DOCUMENTATION = Cougaar.document {
         @description = "Waits for the conditional policies to be finished publishing to one or all enclaves."
         @parameters = [
           {:enclave => "enclave to wait for -- default is nil, meaning all enclaves"},
           {:timeout => "default = nil, Amount of time to wait in seconds."},
           {:block => "The timeout handler (unhandled: StopSociety, StopCommunications"}
         ]
         @example = "
           wait_for 'ConditionalPolicies'
             or
           wait_for 'ConditionalPolicies', 'CONUS-REAR', 10.minutes
         "
       }

       def initialize(run, enclave=nil, timeout=nil, &block)
         super(run, timeout, &block)
         @enclave = enclave
       end
       
       def process
         threads = @run['ConditionalPolicyThreads']
         if (threads == nil)
           @run.warn_message "No conditional policies have been published"
           return nil
         end
         if (@enclave != nil)
           @run.info_message "Waiting for #{@enclave} to finish publishing conditional policies"
         else
           @run.info_message "Waiting for all enclaves to finish publishing conditional policies"
         end
         if (@enclave == nil)
           threads.each_pair { |enclave, thread| 
             @run.info_message "Waiting for enclave #{enclave} to finish publication"
             thread.join
           }
         else
           threads[@enclave].join
         end
       end # perform

       def unhandled_timeout
         @run.do_action "StopSociety"
         @run.do_action "StopCommunications"
       end
     end # ConditionalPolicies
   end # module States
end # Cougaar
