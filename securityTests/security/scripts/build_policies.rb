=begin script

include_path: setup_security.rb
description: special initialization for security

=end

require 'security/lib/scripting'

insert_before :setup_run do
  do_action "BuildPolicies"
  do_action "GenericAction" do |run|
    # First, extract the Java policy from the JAR file to make
    # sure we are working from the original file.
    `cd #{$CIP}/configs/security ; jar xvf configs_secure_bootstrapper.jar security/Cougaar_Java.policy`
    # Rebuild Java policy to accept both
    # old signers and new signers.
    `java -classpath #{$CIP}/lib/secure_bootstrapper.jar org.cougaar.core.security.securebootstrap.PolicyParserTool #{$CIP}/configs/security/security/Cougaar_Java.policy #{$CIP}/configs/security/Cougaar_Java.policy`
  end
end
