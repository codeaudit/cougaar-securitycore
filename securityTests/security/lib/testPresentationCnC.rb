#!/usr/bin/env ruby

$DoDaily = true
$DoTransportDaily = false
$ShowDifferences = true

$LOAD_PATH.unshift '../..'

#require 'security/lib/scripting'
require 'security/lib/analysisOnly'
require 'security/lib/analysisScripting'

#require 'framework/mergeMopAnalysis'
#require 'framework/namedCollection'
#require 'framework/logisticsMop/scripting'
#require 'framework/doIrb'


$DebugMode = true

if true   # do one experiment
  puts "doing one experiment ..."
  cnc = PresentationCnC.new
  #cnc.calculate("/Users/bmd/Desktop/downloads/agg_out")
  #cnc.calculate("JTG2")
  #cnc.calculate("/export/archive42/analysis_data/sv022/1074209424")
  #cnc.calculate("/export/archive42/analysis_data/sv082/1074357669")
  #cnc.calculate("/home/u/bmurphy/UL/PAD/securityTests/security/lib/tests/baseline")
#  cnc.calculate("/home/asmt/CSI/brian/UL/PAD/securityTests/security/lib/tests/baseline")
  file = "/home/asmt/CSI/brian/data/#{ARGV[0]}"
puts file
  cnc.calculate(file)
  #cnc.calculate("/home/u/bmurphy/UL/PAD/securityTests/security/lib/tests/cpustress")
  #cnc.calculate("JTG6")

  puts "<SurvivabilityMetrics>"
  puts cnc.getXMLData
  puts "</SurvivabilityMetrics>"
#  exit
  puts "----------------------------------"
  puts cnc.getMoeValues
  puts "**********************************"
  exit
end


if true   # merge experiments
  n1 = "/export/archive42/analysis_data/sv022/1072488013"
  n2 = "/export/archive42/analysis_data/sv022/1074209424"
  cnc = MergePresentationCnC.new(n1, n2)

  puts "<SurvivabilityMetrics>"
  puts cnc.getXMLData
  puts "</SurvivabilityMetrics>"
  exit
  puts "----------------------------------"
  puts cnc.getMoeValues
  puts "**********************************"
  exit
end



#x = loadAggExperiment("/Users/bmd/Desktop/downloads/agg_out", "experiment")
x = loadAggExperiment("/home/u/bmurphy/UL/PAD/securityTests/security/lib/", "experiment")


puts "printing jp8 diffs (ojp8 as baseline)"
result = x['iba_jp8.xml'].diff(x['oba_jp8.xml'], PostPartDiffs2.new)
puts 'asdfjfdsksdjdfsjklfdjklfdsjkldfsjkldfjsklfdskjlfds'
showTotalByUnits(result)

puts "calculating cnc mops"
mops = CompletenessCorrectnessDiffs.new
result = x['iba_shortfall.xml'].diff(x['oba_shortfall.xml'], mops)
puts mops
result = x['iba_jp8.xml'].diff(x['oba_jp8.xml'], mops)
puts mops
puts "completeness mop = #{mops.completenessMop}"
puts "correctness  mop = #{mops.correctnessMop}"

