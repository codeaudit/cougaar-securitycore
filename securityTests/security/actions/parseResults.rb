#!/usr/bin/ruby
#
# Check that all expected tests have been executed
# Parse the test results file: $CIP/workspace/test/security_test_results.xml
# 
#
# The script can be invoked outside a running society to generate a report:
#  -g              : generates report and save it as
#  -i <filename>   : use filename as input file instead of default
#  -o <filename>   : save output file as filename instead of default

generateReport = false
inputFile = nil
outputFile = nil

if !defined? CIP
  CIP = ENV['CIP']
end
require 'cougaar/scripting'
require 'ultralog/scripting'
require 'ftools'

while ( ARGV.size > 0) do
  p = ARGV.shift
  if p =~ /^-g/
    generateReport = true
  elsif p =~ /^-i/
    inputFile = ARGV.shift
  elsif p =~ /^-o/
    outputFile = ARGV.shift
  end
end

$defaultSecResultsInputFile = "#{CIP}/workspace/test/security_test_results.xml"
$defaultSecResultsOutputFile = "#{CIP}/workspace/test/security_test_final_results.xml"

$expectedTests = [
  'SecurityMop2.1', 'SecurityMop2.2', 'SecurityMop2.3',
  'SecurityMop2.4', 'SecurityMop2.5', 'SecurityMop2.6',
  'Stress1e1', 'Stress1e2',
  'Stress3a101',
  'Stress3b9', 'Stress3c9',
  'Stress3c21',
  'Stress3c2', 'Stress3c5',
  'Stress3c1',
  'Stress3e1', 'Stress3e2',
  'Stress4a50', 'Stress4a51', 'Stress4a52', 'Stress4a53',
  'Stress4a201',
  'Stress4a60', 'Stress4a61', 'Stress4a62', 'Stress4a63',
  'Stress5a1', 'Stress5a2', 'Stress5a3', 'Stress5a4',
  'Stress5a101',
  'Stress5a20', 'Stress5a21', 'Stress5a22', 'Stress5a23',
  'Stress5f',
  'Stress5k103', 'Stress5k104',
  'StressMaliciousJoinCommunity',
]


module Cougaar
  module Actions

   class ParseSecurityResults < Cougaar::Action
     def initialize(run, filename=$defaultSecResultsInputFile)
       super(run)
       @filename = filename
       @rp = ResultParser.new(@filename)
     end

     def perform()
       @rp.parseResults()
     end
   end

   class LogPlannedSecurityExperiments < Cougaar::Action
     def initialize(run, filename=$defaultSecResultsInputFile)
       super(run)
       @filename = filename
       @rp = ResultParser.new(@filename)
     end

     def perform()
       @rp.logPlannedSecurityExperiments()
     end
   end

  end
end

class ResultParser
  def initialize(inputFile=$defaultSecResultsInputFile,
                 outputFile=$defaultSecResultsOutputFile) 
    @filename = inputFile
    @xmlFile = outputFile
    @testsFound = []
    @missingTests = []
    @experimentMissingTests = []
  end

  def fixXmlFile
    aFile = File.new(@filename, "r")
    begin
      outputDir = File.dirname(@xmlFile)
      File.copy("#{CIP}/csmart/lib/security/actions/results.xsl", outputDir)
    rescue => ex
      puts "Unable to copy XSL stylesheet to #{outputDir}: #{ex}"
    end

    outputFile = File.new(@xmlFile, "w")
    outputFile << "<?xml version='1.0'?>\n"
    outputFile << "<?xml-stylesheet type=\"text/xsl\" href=\"results.xsl\"?>\n"
    outputFile << "<securityResults>\n"

    outputFile << "  <securityEvents>\n"
    aFile.each_line {|line|
      outputFile << "    #{line}"
    }
    outputFile << "  </securityEvents>\n"

    outputMissingTests(outputFile, @testsFound - $expectedTests, "unexpectedTests",
       ["  <!-- Contains tests reported during the experiment but that have not\n",
        "        been listed in the global list of tests. -->\n"])

    outputMissingTests(outputFile, @missingTests, "globalTestList",
       ["  <!-- Contains tests listed in the global list of tests\n",
        "       that were not reported during this particular experiment\n",
        "       Tests may be missing because they have not been configured\n",
        "       for this particular experiment. -->\n"])

    outputMissingTests(outputFile, @experimentMissingTests, "experimentTestList",
	["  <!-- Contains tests that were configured for this run.\n",
	 "       Results should have been reported but were not. -->\n",
	 "       This could be caused by a scripting error or a society error -->\n"])

    outputFile << "</securityResults>\n"
    aFile.close
    outputFile.close
  end

  def outputMissingTests(outputFile, missingList, tag, comments)
    outputFile << "  <#{tag}>\n"
    comments.each { |t|
      outputFile << t
    }
    missingList.each { |t|
      outputFile << "    <missingTest>#{t}</missingTest>\n"
    }
    outputFile << "  </#{tag}>\n"
  end

  def findMissingTests() 
    aFile = File.new(@filename, "r")
    testIdPattern = "<testId>(.*?)</testId>"
    plannedTestPattern = "<plannedTest>(.*?)</plannedTest>"
    plannedTests = []
    aFile.each_line { |line|
      line.scan(/#{testIdPattern}/) { |x|
	#puts "Test found: #{x[0]}" 
	@testsFound << x[0]
      }
      line.scan(/#{plannedTestPattern}/) { |x|
	#puts "Planned Test found: #{x[0]}" 
	plannedTests << x[0]
      }
    }
    @missingTests = $expectedTests - @testsFound

    if defined? $configuredSecurityTests
      @experimentMissingTests = $configuredSecurityTests - @testsFound
    else
      @experimentMissingTests = plannedTests - @testsFound
    end
    aFile.close
  end

  def logPlannedSecurityExperiments()
    aFile = File.new(@filename, File::APPEND | File::RDWR)
    aFile << "<plannedSecurityExperiments>\n"
    if defined? $configuredSecurityTests
      $configuredSecurityTests.each { |test|
	aFile << "  <plannedTest>#{test}</plannedTest>\n"
      }
    end
    aFile << "</plannedSecurityExperiments>\n"
    aFile.close
  end

  def parseResults()
    findMissingTests()
    fixXmlFile()
  end

end

def testParseResults(inputFile, outputFile)
  rp = ResultParser.new(inputFile, outputFile)
  #rp.logPlannedSecurityExperiments()
  rp.parseResults()
end

if generateReport
  if (inputFile == nil) 
    inputFile = $defaultSecResultsInputFile
  end
  if (outputFile == nil)
    outputFile = $defaultSecResultsOutputFile
  end
  puts "Generate Report: #{generateReport}"
  puts "Input file:      #{inputFile}"
  puts "Output file:     #{outputFile}"

  testParseResults(inputFile, outputFile)
end
