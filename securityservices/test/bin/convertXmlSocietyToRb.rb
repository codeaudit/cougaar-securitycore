CIP = ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require 'security/scripts/setup_scripting'
require 'security/lib/common_security_rules'

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging

include Cougaar

puts "On TIC societies this operation uses a ton of memory can"
puts "take 20 minutes or more but the resulting file can be processed"
puts "much more quickly."

if (ARGV.length == 0) then
   xmlFile = "mySociety.xml"
   puts "Using #{xmlFile} as the source"
else
   xmlFile = ARGV[0]
end

if xmlFile[-4,4] != ".xml" then
   puts "Usage is #{$0} xmlFileName"
else 
   rubyFile = xmlFile[0..-5] + ".rb"
end
puts "Converting #{xmlFile} to #{rubyFile}"

Cougaar.new_experiment("Test").run(1) do
  do_action "LoadSocietyFromXML", xmlFile
  do_action "SaveCurrentSociety", rubyFile
end


