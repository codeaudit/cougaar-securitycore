
CIP=ENV['CIP']

$:.unshift File.join(CIP, 'csmart', 'lib')

require 'cougaar/scripting'
require 'ultralog/scripting'
require "security/lib/scripting"
require "security/lib/security"

class TestReportChainReady < SecurityStressFramework
  def initialize(run)
    super(run)
    @run = run
    @expectedSubordinates = Hash.new
    @foundSubordinates    = Hash.new
    @stressid = "ReportChainReady Detector"
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
    logInfoMsg("calling loadSocietyData for report for Duty")
    @run.society.each_agent(true) do |agent|
      facetval = agent.get_facet(:superior_org_id)
      if facetval != nil
        subordinate = agent.name
        superior    = facetval
        addExpectedRelation(subordinate, superior)
      end
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

  def afterReportChainReady
    Thread.fork do
      logInfoMsg("calling afterReportChainReady for reportforDuty script")
      begin
        badChains=[]
        4.times do
          sleep(5.minutes)
          badChains = getBadChains ["OSD.GOV"]
          if !(badChains.empty?)
            badChains.each do |chain|
              saveAssertion stressid, 
                            "ReportChainReady failed at subordinate #{chain.last}"
              explanation = "Subordinate chain = #{chain.join("->")}"
              saveAssertion stressid, explanation
            end
          end
        end
        logInfoMsg("calling Save results in afterReportChainReady for reportforDuty script")
        if badChains.empty?
          saveResult false, stressid, "ReportChainReady failed"
        else
          saveResult true, stressid, "ReportChainReady succeeded"
        end 
      rescue => ex
        puts "error in afterReportChainReady"
        puts "#{e.class}: #{e.message}"
        puts e.backtrace.join("\n")
        saveAssertion stressid, "Exception = #{ex}\n #{ex.backtrace.join('\n')}"
      end
    end
  end

  def getBadChains stack
    superior  = stack.last
    expected  = @expectedSubordinates[superior]
    found     = @foundSubordinates[superior]
    badChains = []
    if expected == nil || expected.empty?
      return badChains
    end
    expected.each do |expectedSub|
      if ((found == nil) || (! found.include? expectedSub))
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
    regexp = /Interception: ReportForDuty with role : <(.*)> : <(.*)> : (.*)/
    parsed = regexp.match(line)
    if parsed != nil
      subordinate = parsed.to_a[1].split(" ").last
      superior    = parsed.to_a[2].split(" ").last
      role        = parsed.to_a[3]
      if role == "Subordinate"
        if (@foundSubordinates[superior] == nil)
          @foundSubordinates[superior] = []
        end
        @foundSubordinates[superior].push(subordinate)
      end
    end
  end

  def processEventsFromFile
    filename = File.join(ENV["CIP"], "workspace", "test", "acme_events.log")
    File.open(filename) do |file|
      file.readlines.each do |line|
        parseLine(line)
      end
    end
    puts("getting ready to calculate bad chains")
    getBadChains(['OSD.GOV']).each do |chain|
      puts("Found bad chain ending at #{chain.last}")
      puts("Chain = " + chain.join(' -> '))
    end
  end
end
