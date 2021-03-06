if ! defined? CIP
  CIP=ENV['CIP']
end

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require "security/lib/scripting"
require "security/lib/security"

class TestReportChainReady < SecurityStressFramework
  def initialize(run)
    super(run)
    @run = run
    @expectedSubordinates   = Hash.new
    @foundSubordinates      = Hash.new
    @stressid = "ChainReady"
    @cmdline  = false
  end

  def getStressIds
    return [@stressid]
  end

  def beforeStartedSociety
    loadSocietyData
    @run.comms.on_cougaar_event do |event|
      eventCall(event)
    end
  end

  def loadSocietyData
    File.open(File.join(CIP, "workspace", "test", "subordinates.rb"), "w") do |rubyFile|
      logInfoMsg("calling loadSocietyData for report for Duty") if $VerboseDebugging
      rubyFile.puts("def installExpectedRelations(rcr)")
      @run.society.each_agent(true) do |agent|
        facetval = agent.get_facet(:superior_org_id)
        if facetval != nil
          subordinate = agent.name
          superior    = facetval
          addExpectedRelation(subordinate, superior)
          rubyFile.puts "  rcr.addExpectedRelation(\"#{subordinate}\", \"#{superior}\")"
        end
      end
      rubyFile.puts("end")
    end
  end

  def addExpectedRelation(subordinate, superior)
    if  @expectedSubordinates[superior] == nil
      @expectedSubordinates[superior]  = [] 
    end
    if !(@expectedSubordinates[superior].include?(subordinate))
      @expectedSubordinates[superior].push(subordinate)
    end
  end

  def addFoundSubordinate(subordinate, superior)
    #    puts "addFound - #{subordinate} / #{superior}"
    if (@foundSubordinates[superior] == nil)
      @foundSubordinates[superior] = []
    end
    @foundSubordinates[superior].push(subordinate)
  end

  def afterReportChainReady
    if ! checkBlackBoardCollectorPlugin then
      logInfoMsg("BlackBoardCollectorPlugin not installed")
      logInfoMsg("Script for testing Report Chain Ready status exiting...")
      logInfoMsg("Command line report chain ready tester won't work either")
      return
    end
    Thread.fork do
      logInfoMsg("calling afterReportChainReady for reportforDuty script") if $VerboseDebugging
      begin
        success = true
        4.times do
          sleep(5.minutes)
          success = generateReport()
        end
        logInfoMsg("calling Save results in afterReportChainReady for reportforDuty script") if $VerboseDebugging
        if success then
          saveResult true, @stressid, "ReportChainReady succeeded - all agents reported for duty"
        else
          saveResult false, @stressid, "ReportChainReady failed - some agents did not report for duty"
        end 
      rescue => ex
        logInfoMsg("error in afterReportChainReady #{ex} #{ex.backtrace.join("\n")}")
        saveAssertion @stressid, "Exception = #{ex}\n #{ex.backtrace.join("\n")}"
      end
    end
  end

  def getBadChains stack
    superior  = stack.last
    if @cmdline then
      puts "Working on #{superior}"
    end
    expected  = @expectedSubordinates[superior]
    found     = @foundSubordinates[superior]
    if @cmdline then
      if found then
        puts "These subordinates reported: #{found.join(" ")}"
      else 
        puts "No subordinates reported"
      end
    end
    badChains = []
    if expected == nil || expected.empty?
      return badChains
    end
    expected.each do |expectedSub|
      if @cmdline then
        puts "Looking at expected subordinate #{expectedSub}"
      end
      if ((found == nil) || (! found.include? expectedSub))
        if @cmdline then
          puts "subordinate did not report"
        end
        newStack     = stack.clone.push expectedSub
        newBadChains = getBadChains newStack
        if newBadChains.empty?
          badChains.push newStack
        else
          badChains.concat newBadChains
        end
      end
    end
    return badChains
  end

  def eventCall(event)
    parseLine(event.data)
  end

  def parseLine(line)
    regexp = /Interception: ReportChainReady : (.*) : (.*)$/
    parsed = regexp.match(line)
    if parsed != nil
      subordinate = parsed.to_a[1].split(" ").last
      superior    = parsed.to_a[0].split(" ").last
      if (!(subordinate == superior)) then
        addFoundSubordinate(subordinate, superior)
      end
    end
  end

  def processEventsFromFile
    @cmdline = true
    filename = File.join(ENV["CIP"], "workspace", "test", "acme_events.log")
    File.open(filename) do |file|
      file.readlines.each do |line|
        parseLine(line)
      end
    end
    if (@foundSubordinates.empty?) then
      puts("No subordinates appear to have reported.  This could mean:")
      puts("\t1. no subordinates reported")
      puts("\t2. The BlackBoardCollectorPlugin is missing")
      puts("\t\tUse the rule ServiceContractPlugin.rule")
      puts("\t3. Events aren't finding their way into acme_events.log")
      exit(-1)
    end    
    puts("getting ready to calculate bad chains")
    generateReport()
  end

  def generateReport()
    badChains = getBadChains ["OSD.GOV"]
    if !(badChains.empty?)
      explanation = "ReportChainReady failed at #{badChains.size()} subordinates:\n"
      sortedBadChains = badChains.sort { |x, y|
        x.last <=> y.last
      }
      sortedBadChains.each do |chain|
        explanation += "#{chain.reverse.join("->")}\n"
      end
      print explanation
    else 
      print "All agents reported for duty"
    end
    badChains.empty?
  end

  def checkBlackBoardCollectorPlugin ()
    scPlugin = "org.cougaar.core.security.test.BlackBoardCollectorPlugin"
    @run.society.each_agent do |agent|
      #puts "Looking at agent #{agent.name}"
      #puts "target plugin name = #{scPlugin}"
      agent.each_component do |component|
        #puts "looking at component #{component.classname}"
        if component.classname == scPlugin then
          #puts "Found the component!"
          return true
        end
      end
      break
    end
    return false
  end

  def print(msg)
    if @cmdline then
      puts(msg)
    else
      saveAssertion @stressid, msg
    end
  end
end

