#!/usr/bin/ruby

CIP=ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require "security/lib/scripting"
require "security/lib/security"
require "security/lib/stresses/reportChainReady"

require File.join(CIP, "workspace", "test", "subordinates.rb")

x = TestReportChainReady.new(nil)
installExpectedRelations(x)
x.processEventsFromFile
