
# This file provides web requests to the hosts, etc.

require 'lib/scripting'

class ExperimentFramework
   def checkHostTomcatServers
      port = run.society.cougaar_port
      hosts = run.society.agents
      checkTomcatServers(hosts, port)
   end

end
