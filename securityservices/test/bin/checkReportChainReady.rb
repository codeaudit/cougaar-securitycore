#!/usr/bin/ruby

CIP=ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require "security/lib/scripting"
require "security/lib/security"
require "security/lib/stresses/reportChainReady"

Cougaar.new_experiment().run(1) do
  do_action "LoadSocietyFromXML", "mySociety.xml"
#  do_action "LayoutSociety", "mySociety.xml"
  puts "here i am"
  do_action "GenericAction" do |run|
    run.society.each_enclave do |enclave|
      puts "enclave = #{enclave}"
    end
  end

  do_action "InjectStress", "TestReportChainReady", "beforeStartedSociety"
  do_action "InjectStress", "TestReportChainReady", "processEventsFromFile"
end


