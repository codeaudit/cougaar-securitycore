require 'cougaar/scripting'
require 'ultralog/scripting'
begin
  require 'assessment/scripting'
rescue Exception => e
  puts "error while loading assessment/scripting, will skip ..."
end
require 'framework/cougaarMods'

require 'framework/doIrb'
require 'framework/experimentFramework'

require 'framework/summary'
require 'framework/rules'
require 'framework/web'
require 'framework/misc'
require 'framework/webFramework'
require 'framework/userDomain'
require 'framework/loadSociety'
require 'framework/useExperiment'
require 'framework/checkAllJabberHosts'
require 'framework/caDomain'
require 'framework/security'
require 'framework/configFiles'
begin
  require 'framework/securityMop'
rescue LoadError => e
  # globals.rb doesn't exist for security services
  puts "didn't load securityMop.rb"
end
require 'framework/securityMopActions'
require 'framework/mergeMopAnalysis'
require 'framework/namedCollection'
# require 'framework/securityMopAnalysis'

require 'framework/dataProtection'

require 'framework/runSecurity'
begin
  require 'framework/policy_util'
rescue Exception
  puts "WARNING:  couldn't load framework/policy_util"
end
require 'framework/society_util'
require 'framework/message_util'
begin
  require 'framework/cond_policy.rb'
rescue Exception
  puts "WARNING: not loading framework/cond_policy.rb -- does not exist"
end
