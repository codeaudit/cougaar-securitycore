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

require 'ftools'

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


$styleSheetContents=<<END
<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
  <body>
    <h2>Security Experiment Results</h2>
    <xsl:apply-templates/> 
  </body>
  </html>
</xsl:template>

<xsl:template match="experimentTestList">
    <h3>Missing Security Test Cases</h3>
    This table lists security tests that were configured for this run.<br/>
    Security Test Case Results should have been reported but were not.<br/>
    This could be caused by a scripting error or a society error.<br/>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th align="left">Name</th>
      </tr>
      <xsl:for-each select="missingTest">
        <tr>
          <td><xsl:value-of select="."/></td>
        </tr>
      </xsl:for-each>
    </table>
</xsl:template>

<xsl:template match="securityEvents">

    <h3>Security Test Case Results</h3>
    <table border="1">
    <tr bgcolor="#9acd32">
      <th align="left">Time</th>
      <th align="left">TestId</th>
      <th align="left">Description</th>
    </tr>
    <xsl:for-each select="event">
    <tr>
      <xsl:choose>
      <xsl:when test="success='true'">
        <!-- #33ff33 : Green --> 
        <td bgcolor="#33ff33"><xsl:value-of select="date"/></td>
        <td bgcolor="#33ff33"><xsl:value-of select="testId"/></td>
        <td bgcolor="#33ff33"><xsl:value-of select="description"/></td>
      </xsl:when>
      <xsl:otherwise>
        <!-- #ff6633 : Red --> 
        <td bgcolor="#ff6633"><xsl:value-of select="date"/></td>
        <td bgcolor="#ff6633"><xsl:value-of select="testId"/></td>
        <td bgcolor="#ff6633"><xsl:value-of select="description"/></td>
      </xsl:otherwise>
      </xsl:choose>
    </tr>
    </xsl:for-each>
    </table>

    <br/>
    <h3>Security Planned Test Cases</h3>
    <table border="1">
    <tr bgcolor="#9acd32">
      <th align="left">Test Case Name</th>
    </tr>
    <xsl:for-each select="plannedSecurityExperiments/plannedTest">
      <tr>
        <td><xsl:value-of select="."/></td>
      </tr>
    </xsl:for-each>
    </table>

    <br/>
    <h3>Security Unit Test Results</h3>
    <table border="1">
    <tr bgcolor="#9acd32">
      <th align="left">Time</th>
      <th align="left">TestId</th>
      <th align="left">Description</th>
    </tr>
    <xsl:for-each select="unitTestResult">
      <tr>
        <td bgcolor="#CCFFFF"><xsl:value-of select="date"/></td>
        <td bgcolor="#CCFFFF"><xsl:value-of select="testId"/></td>
        <td bgcolor="#CCFFFF"><xsl:value-of select="description"/></td>
      </tr>
    </xsl:for-each>
    </table>
</xsl:template>

</xsl:stylesheet>
END


class ResultParser
  def initialize(inputFile,
                 outputFile) 
    @filename = inputFile
    @xmlFile = outputFile
    @testsFound = []
    @missingTests = []
    @experimentMissingTests = []
  end

  def fixXmlFile
    aFile = File.new(@filename, "r")
    begin
      File.open(File.join(File.dirname(@xmlFile), "results.xsl"), "w") do |file|
	file.puts($styleSheetContents)
      end
    rescue => ex
      puts "Unable to write XSL stylesheet: #{ex}"
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
	 "       Results should have been reported but were not.\n",
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
    aFile = File.new(@filename, File::APPEND | File::RDWR | File::CREAT)
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
