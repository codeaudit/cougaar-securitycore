require 'security/lib/scripting'
require 'security/lib/society_util'

class StressWPRegistration < SecurityStressFramework
  def initialize
    puts "StressWPRegistration is in the society"
    @started = false
#    startTesting(15.minutes)
  end
  def postStartSociety
#    puts "postStartSociety"
    startTesting
#    puts "postStartSociety done"
  end

=begin
  def preKeepSocietySynchronized
    puts "postStartSociety"
    startTesting
    puts "postStartSociety done"
  end

  def postLoadSociety
    puts "postLoadSociety"
    startTesting
    puts "postLoadSociety done"
  end
    
  def postConditionalStartSociety
    puts "postConditionalStartSociety"
    startTesting
    puts "postConditionalStartSociety done"
  end
=end
  def startTesting(delay = 5.seconds)
    if (!@started)
      @started = true
      testAgentRegistrations(30.seconds, delay) { |missing, expected|
	if missing.empty?
        summary "#{Time.now}: All agents have registered"
      else
        summary "#{Time.now}: Missing #{missing.length} agents: #{missing.join(" ")}"
      end
      }
    end
  end
end # StressWPRegistration
