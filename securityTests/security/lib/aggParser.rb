#!/usr/bin/env ruby

=begin
This file is used for parsing agg agent data (agg_*.xml).
The data is read into a heirarchical structure and then marshalled
out to a file (agg.db).


Each item in a NamedHash, NamedArray, or NamedSummer collection
has a name and is associated with a hash.
This is a heirarchical structure, in which parents and children
  knows about each other.
The public interface is:
  each, []=, size, append, values, append, <<, match?, preDoDepth
  preDoDepthWithValue, doDepth, postDoDepth, postDoDepthWithValue
NamedHash also has:
  each_key, each_value
NamedArray also has:
  sort

----Inheritence Heirarchy
NamedHash
  NamedArray
    NamedSummer (sum)
    PostPart (atoms=hash, rateTotal, dayTotal, average)
  ExperimentResults (files=hash, path, modificationTime), sub=PostFile
  PostFile (agents=hash), sub=PostAgent
  PostAgent (agents=hash), sub=PostPart
    PostAgentSummer, sub=NamedSummer

----Agg data heirarchy
ExperimentResults
  PostFile
    PostAgent
      PostPart

=end

require 'rexml/document'
#require '../namedCollection'
#require '../doIrb'
require 'pstore'
require 'singleton'

include REXML

AggDatabaseName = "agg.db"

# If no argument is passed, use this as a default.
docFilename = 'agg_jp8.xml'
docFilename = ARGV[0] if ARGV.length>0

class ExperimentResultsRepository
   include Singleton
   attr_accessor :directory, :db, :dbname

   def initialize(dbname=AggDatabaseName)
      @dbname = dbname
   end

   def storeAggResults(name, descript, experiment)
      ensureDbIsOpen
      # compress as much as possible
      experiment.replaceWithTotalAtoms
      @db.transaction do |db|
         @directory = db['directory']
         @directory = {} unless @directory
      end
      @directory[name] = descript
      @db.transaction do |db|
         db['directory'] = @directory
         db[name] = experiment
         db.commit
      end
   end

   def loadDirectory
      ensureDbIsOpen
      dir = nil
      @db.transaction do |db|
         dir = db['directory']
      end
      return dir
   end

   def loadAggResults(name)
      ensureDbIsOpen
      experiment = nil
      @db.transaction do |db|
         experiment = db[name]
      end
      return experiment
   end

   def ensureDbIsOpen
      @db = PStore.new(dbname) unless @db
   end
end


###########################################################



class ExperimentResults < NamedHash
  attr_accessor :path, :modificationTime, :exceptionFiles, :missingFiles, :nearTermDivider, :discardDivider
  alias files children
  def initialize(name)
    super(name)
    @exceptionFiles = []
    @missingFiles = []
  end
  def self.defaultSubsequenceClass
    return PostFile
  end
  def replaceWithTotalAtoms
    # intention is compress the individual atoms with one "total" atom.
    self.doDepthNoPrint do |depth, part|
      part.replaceWithTotalAtom
    end
  end
  def has_key?(key)
    @children.has_key?(key)
  end
end
class PostFile < NamedHash
  alias agents children
  def self.defaultSubsequenceClass
    return PostAgent
  end
  def discardDivider
    return parent.discardDivider
  end
  def nearTermDivider
    return parent.nearTermDivider
  end
end
class PostAgent < NamedHash
  alias parts children
  def self.defaultSubsequenceClass
    return PostPart
  end
  def discardDivider
    return parent.discardDivider
  end
  def nearTermDivider
    return parent.nearTermDivider
  end
end
class PostPart < NamedArray
  alias atoms children
  def to_s
    return "#{parent.parent.name}, #{parent.name}, #{name}"
  end
  def discardDivider
    return parent.discardDivider
  end
  def nearTermDivider
    return parent.nearTermDivider
  end
  def replaceWithTotalAtom
    @children = [makeAtomTotal]
  end
  def rateTotal
    unless defined? @rateTotalVar
      total = 0.0
      children.each {|atom|
        total = total + atom.rate * atom.days if atom.rate
      }
      @rateTotalVar = Float(total)
    end
    return @rateTotalVar
  end
  def dayTotal
    unless defined? @dayTotalVar
      total = 0
      children.each {|atom| total = total + atom.days}
      @dayTotalVar = total
    end
    return @dayTotalVar
  end
  def prefDayTotal
    unless defined? @prefDayTotalVar
      total = 0
      children.each {|atom| total = total + atom.prefDays}
      @prefDayTotalVar = total
    end
    return @prefDayTotalVar
  end
  def average
    if dayTotal != 0
      return rateTotal / dayTotal
    else
      return 0.0
    end
  end
  def totalRateTimesDays
    total = 0
    return children.inject(0) {|sum,atom| sum += atom.rateTimesDays}
  end
  def totalRateTimesDaysPlus1
    total = 0
    return children.inject(0) {|sum,atom| sum += (atom.endTime - atom.startTime + 1) * atom.rate}
  end
  def makeAtomTotal
    atom = DataAtom.new
    atom.name = self[0].name
    atom.startTime = 0
    atom.endTime = self.dayTotal
    if atom.endTime and atom.endTime != 0
      atom.rate = Float(self.rateTotal) / atom.endTime
    else
      puts "oops, no end time in aggParser.PostPart.makeAtomTotal"
      #atom.rate = Float(self.rateTotal)
    end
    if self.prefEndTime
      atom.prefStartTime = 0
      atom.prefEndTime = self.prefEndTime - self.prefStartTime
    end
    atom.fromLoc = self.fromLoc
    atom.toLoc = self.toLoc
    return atom
  end
end


class PostAgentSummer <PostAgent
   def self.defaultSubsequenceClass
      return NamedSummer
   end
end

class DataAtom
   include Comparable
   attr_accessor :name, :startTime, :endTime,
        :rate,    # specific to non-transport aggagents
        :prefStartTime, :prefEndTime, :fromLoc, :toLoc # specific to transport

   def initialize(name='', startTime=nil, endTime=nil, rate=nil, prefStartTime=nil, prefEndTime=nil, fromLoc=nil, toLoc=nil)
      @name = name
      @startTime = startTime
      @endTime = endTime
      @rate = rate
      @prefStartTime = prefStartTime
      @prefEndTime = prefEndTime
      @fromLoc = fromLoc
      @toLoc = toLoc
   end

   def to_s
     "DataAtom name=#{name}, time:start=#{startTime},end=#{endTime}, rate=#{rate}, loc:from=#{fromLoc},to=#{toLoc}, prefTime:start=#{prefStartTime},end=#{prefEndTime}"
   end

   def <=>(other)
     if transport?
       result = self.prefStartTime <=> other.prefStartTime
       return result if result != 0
       result = self.prefEndTime <=> other.prefEndTime
       return result if result != 0
=begin
       result = self.fromLoc <=> other.fromLoc
       return result if result != 0
       result = self.toLoc <=> other.toLoc
       return result if result != 0
=end
     else
       result = self.startTime <=> other.startTime
       return result if result != 0
       result = self.endTime <=> other.endTime
       return result if result != 0
     end

     return 0
   end
   def transport?
     return rate == nil
   end

   def discardTerm?(parent)
#bmd
#puts "discard? #{self.startTime} < #{parent.discardDivider}"
     return self.startTime < parent.discardDivider
   end
   def nearTerm?(parent)
#puts "near? #{parent.discardDivider} <= #{self.prefStartTime} < #{parent.nearTermDivider}"
     return ((parent.discardDivider <= self.prefStartTime) and (self.prefStartTime < parent.nearTermDivider))
   end
   def farTerm?(parent)
#puts "far? #{parent.nearTermDivider} <= #{self.prefStartTime}"
     # return !nearTerm?(parent)
     return parent.nearTermDivider <= self.prefStartTime
   end

   def days
      if endTime and startTime
        if transport?
          return endTime - startTime + 1
        else
          return endTime - startTime
        end
      else
        return 0
      end
   end
   def prefDays
      if prefEndTime and prefStartTime
        return prefEndTime - prefStartTime + 1
      else
        return 0
      end
   end
   def rateTimesDays
     return (endTime - startTime) * rate
   end
end

=begin
def parseCommunitiesFile
   doc = Document.new('/mnt/shared/socV4/configs/common/communities.xml')
   doc.elements['/Communities'].each do |community|
      communityName = community.attribtues['Name']
# todo
   end
end
=end

class ExperimentResults
=begin
  def getAggAgentNames(experiment, pattern)
    experiment.keys.grep(pattern)
  end

  def findStageName(experiment)
    names = getAggAgentNames(experiment, /^[io]ba_/)
    if !names.empty?
      match = names[0].scan(/^[io]ba.*Stage([^_.]*)/)
      if !match.empty?
        return "Stage#{match[0][0]}"
      else
        return NoStage
      end
    else
      return NoStage
    end
  end
=end

=begin
  def findStageName
    names = getAggAgentNames(/^[io]ba_/)
    if !names.empty?
      match = names[0].scan(/^[io]ba.*Stage([^_.]*)/)
      if !match.empty?
        return "Stage#{match[0][0]}"
      else
        return NoStage
      end
    else
      return NoStage
    end
  end
=end

  def findStageName(filename)
    runlog = RunLog.new(filename)
    firstline = runlog.rawlines[0]
    if ((m = /^\[INFO\].*(Stage[\d]*).*/.match(firstline)) != nil)
      return m[1]
    end
    return NoStage
  end

  def getAggAgentNames(pattern)
    keys.grep(pattern)
  end

  def readAggFile(path, name, filename)
    puts "Reading #{filename}"
    file = self[filename]
    doc=Document.new(File.new(path+'/'+filename))

    resultSet = doc.elements['/result_set']

    unless resultSet
      resultSet = []
      agentName = filename
#      @exceptionFiles << "#{agentName} was missing"
      @exceptionFiles << "#{filename} has agents missing"
      @missingFiles << agentName
      puts "  #{agentName} was missing" if $VerboseDebugging
      agent = file[agentName]
    end

    haveReportedExceptions = false
    resultSet.each do |agentNode|
      agentName = agentNode.attributes['id']
      if agentName != nil
        puts "  #{agentName}" if $VerboseDebugging
        agent = file[agentName]
        agentNode.elements.each do |atomNode|

          atom = DataAtom.new
          atomNode.elements.each do |id|
            name = id.attributes['name']
            value = id.attributes['value']
            case name
            when "item", "asset"  # asset is for transport
              atom.name = value
            when "start time", "start_time", "alloc_start_time"
              atom.startTime = Integer(value)
            when "end time", "end_time", "alloc_end_time"
              atom.endTime = Integer(value)
            when "rate"
              atom.rate = Float(value)
            when "pref_start_time"
              atom.prefStartTime = Integer(value)
            when "pref_end_time"
              atom.prefEndTime = Integer(value)
            when "from_loc"
              atom.fromLoc = value
            when "to_loc"
              atom.toLoc = value
            else
              puts "error in readAggData, current agent is #{agentName}"
            end
          end
          agent[atom.name] << atom
        end
      else
        agentName = agentNode.attributes['clusterId']
#        @exceptionFiles << "#{agentName} had an exception" this resulted in tons of msgs
        @exceptionFiles << "#{filename} has agent exceptions" unless haveReportedExceptions
        haveReportedExceptions = true
        puts "  exception #{agentName}" if $VerboseDebugging
        agent = file[agentName]
      end
    end

    file.each_value do |agent|
      agent.each_value do |part|
        part.sort
      end
    end
#    return agents
  end
end


#######################   Load Experiments into database

def processNewExperiments(path='.')
  experimentDirs = Dir.entries(path).grep(/^JTG-/)
  directory = ExperimentResultsRepository.instance.loadDirectory
  if directory
    processedExperiments = directory.keys
  else
    processedExperiments = []
  end
  needToProcess = experimentDirs - processedExperiments
  needToProcess.each {|name| processAggExperiment(path, name)}
end

def processAggExperiment(path, name)
  experiment = loadAggExperiment(path, name)
  ExperimentResultsRepository.instance.storeAggResults(name, name, experiment)
  return experiment
end

def loadAggExperiment(path, name, pattern=/^[io]ba_.*xml$/)
  experiment = ExperimentResults.new(name)
  files = Dir.entries(path).grep(pattern)
  files.sort.each {|file| experiment.readAggFile(path, name, file)}
  return experiment
end


def showPart(indent, partArray)
   name = (partArray.name+' '*40)[0,20]
   dayTotal = (' '*40+String(partArray.dayTotal.round).split('.')[0])[-15..-1]
   rateTotal = (' '*40+String(partArray.rateTotal.round).split('.')[0])[-15..-1]
   average = (' '*40+String(partArray.average.round).split('.')[0])[-15..-1]
   puts '  '*indent+"#{name} #{dayTotal} #{rateTotal} #{average}"
end

def showTotalByUnits(experiment)
  puts '----------'
  puts "Showing total by units"
  experiment.keys.sort.each do |file|
puts file
    experiment[file].doDepth do |indent, partArray|
puts indent
puts partArray.class
      showPart indent, partArray
    end
  end
end

def getTotalByParts(experiment)
  puts '----------'
  puts "Building total by parts heirarchy"
  aggPartFiles = PostFile.new('Total by Parts')
  experiment.keys.each do |file|
    aggParts = aggPartFiles[file]
    experiment[file].doDepth do |indent, partArray|
      #atom = DataAtom.new(partArray.name, 0, partArray.dayTotal, partArray.rateTotal / partArray.dayTotal) if partArray.dayTotal != 0
      atom = DataAtom.new(partArray.name, 0, partArray.dayTotal, partArray.average)
      unless partArray.children.empty?
        child = partArray.children[0]
        atom.fromLoc = child.fromLoc
        atom.toLoc = child.toLoc
        atom.prefStartTime = 0
        atom.prefEndTime = partArray.prefDayTotal
        if child.prefStartTime and child.prefEndTime
          atom.prefEndTime = child.prefEndTime - child.prefStartTime
        else
          amot.prefEndTime = 0
        end
      end
      aggParts[partArray.name] << atom
    end # experiment[file]
    return aggPartFiles  #probably won't be used, but hey, why not?
  end # experiment.keys
  return aggPartFiles
end


class PostPart
  def match?
true
#      name == 'NSN/9130010315816'
  end
end

def showTotalByParts(experiment)
  aggPartFiles = getTotalByParts(experiment)
  puts '----------'
  puts "Showing total by parts"
  aggPartFiles.doDepth do |depth, partArray|
    showPart depth, partArray
  end
end


=begin
experiment.each do |agentName, agent|
   agent.each do |partName, partArray|
     puts "#{partName} (size = #{partArray.size})"
   end
end

=end



###################################################




# public methods:
#   diffBetween(startMsg, endMsg, startOccurrence=1, endOccurrence=1): dur or nil

#   durationFor(msgname [can be a pattern], occurrence=1):  duration or nil
#   timedlines: [ [time1,msg1], [time2,msg2], ...]
#   durationlines: [ [msga,durationa], [msgb,durationb], ...]
class RunLog
  attr_accessor :filename
  #attr_accessor :rawlines, :timedlines, :durationlines
  # rawlines:  [line1,line2,...]
  def initialize(filename='run.log')
    @filename = filename
    @durationlines = @timedlines = @rawlines = nil
  end

  def self.stages
    return [
      # stage name, time to advance to get to this stage, advance description, skip snapshot?
      nil,  # so we can index starting at 1.
      ['Starting Planning Phase Stage - 1', 0, '', true],
      ['Starting Planning Phase Stage - 2', 4, 'AUG 14 (C-1)'],
      ['Starting Planning Phase Stage - 3', 46, 'SEP 29 (C+45)'],
      ['Starting Planning Phase Stage - 4', 11, 'OCT 10 (C+56)'],
      ['Starting Planning Phase Stage - 5', 4, 'OCT 14 (C+60)'],
      ['Starting Planning Phase Stage - 6', 0, '', true],
      ['Starting Planning Phase Stage - 7', 1, 'OCT 15 (C+61)']
      ]
  end
=begin
      ['Stage1_C-5_InitialPlanning', 0, '', true],
      ['Stage2_C-1_2-BDEArrivalDelay', 4, 'AUG 14 (C-1)'],
      ['Stage3_C+45_2BDEOptempoHigh', 46, 'SEP 29 (C+45)'],
      ['Stage4_C+56_InitialUA', 11, 'OCT 10 (C+56)'],
      ['Stage5n6_C+60_UAAssaultAnd1BDEOptempo', 4, 'OCT 14 (C+60)'],
      ['Stage6', 0, '', true],
      ['Stage7_C+61_UAAirAssault', 1, 'OCT 15 (C+61)']
=end

  def firstStage
    first, last = firstAndLastStageNums
    return first
  end

  def lastStage
    first, last = firstAndLastStageNums
    return last
  end

  def firstAndLastStageNums
    firstStage = lastStage = 1
    (1..7).each do |stage|
#bmd
#puts RunLog.stages[stage][0]
      if messageTime(RunLog.stages[stage][0])
        firstStage = stage unless stage
        lastStage = stage
      else
        break
      end
    end
    return firstStage, lastStage
  end

  def durationFor(msgname, occurrence=1)
    begin
      answer = searchFor(durationlines, msgname, occurrence)
    rescue Exception => e
      puts "Error while calculating duration for : #{msgname}"
      puts e.message
      puts e.backtrace.join("\n")
    end
    return answer
  end

  def durationForLast(msgname)
    diffBetweenLast(startMsg, endMsg)
  end

  def diffBetweenLast(startMsg, endMsg)
    startocc = getLastOccuranceNum(startMsg)
    endocc = getLastOccuranceNum(endMsg)
    return diffBetween(startMsg, endMsg, startocc, endocc)
  end

  def getLastOccuranceNum(msgname)
    okay = nil
    1.upto(10) do |n|
      return okay unless searchFor(timedlines, msgname, n)
      okay = n
    end
  end

  def diffBetween(startMsg, endMsg, startOccurrence=1, endOccurrence=1)
    startTime = messageTime(startMsg, startOccurrence)
    endTime = messageTime(endMsg, endOccurrence)
    return nil unless startTime and endTime
    return endTime - startTime
  end

  def messageTime(msgname, occurrence=1)
    return searchFor(timedlines, msgname, occurrence)
  end

  def searchFor(array, msgname, occurrence)
    msgname = Regexp.new(msgname) if msgname.kind_of?(String)
#bmd
#puts msgname
#puts array.inspect
    array.each do |line|
#puts "-- #{line[0]} -- #{line[1]}"
      if line[0] =~ msgname
        return line[1] if occurrence <= 1
        occurrence = occurrence - 1
      end
    end
#exit
    return nil
  end

  def durationlines
    convertTimedLines unless @durationlines
    return @durationlines
  end
  def convertTimedLines
    @durationlines = []
    stack = []
    name = ''
    i = 0
#puts "<<<<<<<<< in convertTimedLines"
    timedlines.each do |line|
      if line[0] =~ /^Starting: /
        name = line[0][10..-1]
        match = name.split('(')
        name = match[0] if match
        l = [name, line[1]]
#puts "***********S #{line[0]}   <#{l[0]}>"
        stack.unshift(l)
      elsif line[0] =~ /^Waiting for: /
        name = line[0][13..-1]
        match = name.split('(')
        name = match[0] if match
        l = [name, line[1]]
#puts "***********W #{line[0]}   <#{l[0]}>"
        stack.unshift(l)
      elsif line[0] =~ /^Finished: / or line[0] =~ /^Done: /
        if line[0][0..0] == 'F'
          name = line[0][10..-1]
        else
          name = line[0][6..-1]
        end
        match = name.split('(')
        name = match[0] if match
#puts "***********F #{line[0]},   stack.size: #{stack.size},  name: <#{name}>"
        stack.size.times do |n|
          begin
#puts ">>>>>>>>>>> #{n}: <#{stack[n][0]}>"
            if stack[n][0] == name
              # pop in case 'finished' isn't printed for one of the started
              (n-1).times {|x| stack.shift}
              @durationlines[i] = [name, line[1]-stack[n][1]]
              i = i + 1
              stack.shift
            end
          rescue Exception => e
            puts "error: #{e.class} #{e.message}"
            puts e.backtrace.join("\n")
            puts line
exit
          end
        end
      end
    end
  end

  def timedlines
#bmd
#puts "in timedlines"
    convertRawLines unless @timedlines
#puts @timedlines.size
    return @timedlines
  end
  def convertRawLines
    @timedlines = []
    i = 0
    rawlines.each do |line|
#puts line
      time, msg = convertTime(line)
#puts "#{time}: #{msg}"
      if time
        @timedlines[i] = [msg, time]
        i = i + 1
      end
    end
  end

  def rawlines
    @rawlines = File.readlines(@filename) unless @rawlines
    @rawlines = @rawlines.collect {|line| line.chomp}
    return @rawlines
  end

  # returns time and message
  def convertTime(line)
    if ( (m = /^\[INFO\] (\w\w\w) (\w\w\w) (\d\d) (\d\d):(\d\d):(\d\d) (\w\w\w) (\d\d\d\d) ::\s+#{value}.*/.match(line)) != nil )
      if (m[7] == "UTC")
        t = Time.utc(m[8].to_i, m[2], m[3].to_i, m[4].to_i, m[5].to_i, m[6].to_i)
      else
        t = Time.local(m[8].to_i, m[2], m[3].to_i, m[4].to_i, m[5].to_i, m[6].to_i)
      end
      return t, m[7]
    end
    return nil, ''
  end

end # class RunLog



#################################

class LMOPscores
  include Singleton

  attr_accessor :name, :descript, :score, :info, :weight

=begin
    [
[['1', 60]
  [['1-1', 40]
    [['1-1-1', 'Equipment Delivery (C&C)', 
=end

end # class LMOPscores

