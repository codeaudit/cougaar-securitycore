#!/usr/bin/ruby

if ! defined? CIP then
  CIP=ENV['CIP']
end

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require "security/lib/scripting"
require "security/lib/security"
require "security/lib/stresses/reportChainReady"

subordinatesFile = File.join(CIP, "workspace", "test", "subordinates.rb")
subordinatesFound=false
begin
  if File.stat(subordinatesFile).readable?() then
# strange inconsistency - require doesn't throw exceptions?
    require subordinatesFile
    subordinatesFound = true
  end
rescue
  puts("#{$!} #{$!.backtrace.join("\n")}")
  puts("------------------------")
  puts("Error reading subordinates.rb")
  puts("The check_report_chain_ready.rb" +
            "script probably wasn't loaded")
  exit(-1)
end

x = TestReportChainReady.new(nil)
installExpectedRelations(x)
x.processEventsFromFile
