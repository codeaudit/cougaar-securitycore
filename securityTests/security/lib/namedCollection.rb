#!/usr/bin/env ruby

=begin
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

=end

$PrintDepth = true
NoStage = 'NoStage'

class NamedHash
  attr_accessor :name, :children, :parent
  def initialize(name='noname')
    setName(name)
    @children = {}
  end
  def setName(name)
    @name = convertName(name)
  end
  def convertName(name)
    return name
    # this doesn't make much difference in storage requirements
    if name.kind_of?(String)
      @name = name.intern
    else
      @name = name
    end
  end
  def name
#    return @name.id2name if @name.kind_of?(Symbol)
    return @name
  end
  def to_ss
    "#{self.class.name}('#{name}'), parent=#{parent.name},
<<#{children.collect {|x, child| child.to_s}.join(', ')}>>"
  end
  def each(&block)
    @children.keys.sort.each do |key|
      block key, @children[key]
    end
  end
  def each_key(&block)
    @children.each_key &block
  end
  def each_value(&block)
    @children.each_value &block
  end
=begin
  def []=(key, value)
    key = convertName(key)
    #key = key.intern if key.kind_of?(String)
    ensureKey(key)
    @children[key] = value
  end
=end
  def [](key)
    key = convertName(key)
    #key = key.intern if key.kind_of?(String)
    ensureKey(key)
    @children[key]
  end
  def size
    @children.size
  end
  def keys
    @children.keys
  end
  def values
    @children.values
  end
  def append(value)
    @children << value
  end
  alias << append
  def ensureKey(key)
    unless @children.has_key? key
      child = self.class.defaultSubsequence(key)
      @children[key] = child
      child.parent = self
    end
  end
  def self.defaultSubsequenceClass
    return Hash
  end
  def self.defaultSubsequence(key)
    return self.defaultSubsequenceClass.new(key)
  end

  def preDoDepth(depth)
     puts '  '*depth+name if $PrintDepth
  end
  def preDoDepthWithValue(depth, value)
  end
  def doDepth(depth=0, &block)
    if self.kind_of? NamedArray
      yield depth, self
    else
      preDoDepth(depth)
      (values.sort {|a,b| a.name<=>b.name}).each do |value|
        if value.match?
          preDoDepthWithValue(depth, value)
          value.doDepth depth+1, &block
          postDoDepthWithValue(depth, value)
        end
      end
      postDoDepth(depth)
    end
  end
  def postDoDepthWithValue(depth, value)
  end
  def postDoDepth(depth)
  end
  def doDepthNoPrint(depth=0, &block)
    printDepth = $PrintDepth
    $PrintDepth = false
    begin
      doDepth(depth, &block)
    ensure
      $PrintDepth = printDepth
    end
  end

  def diff(other, diffMethods)
    result = self.class.new('result')
    result.parent = self.parent
    difference(0, result, self, other, diffMethods)
    diffMethods.finish
    return result
  end

  def difference(depth, result, from, to, diffMethods)
    runPreDiff(diffMethods, depth, result, from, to)
    if from.kind_of?(NamedArray) or (from==nil and to.kind_of?(NamedArray))
      leafDiff(depth, result, from, to, diffMethods)
    else
      nodeBranchDiff(depth, result, from, to, diffMethods)
    end
    runPostDiff(diffMethods, depth, result, from, to)
  end

  def leafDiff(depth, result, from, to, diffMethods)
    magnitude = compareFromTo(from, to)
    if magnitude < 0
      diffMethods.added(depth, result, to)
    elsif magnitude > 0
      diffMethods.removed(depth, result, from)
    else # magnitude == 0
      diffMethods.inBoth(depth, result, from, to)
    end
  end

  def filter(itemArray, diffMethods)
    return itemArray unless itemArray and itemArray != []
    c = itemArray[0].class
    f = diffMethods.classFilters[c]
    if f
      return itemArray.select(&f)
    else
      return itemArray
    end
  end

  def runPreDiff(diffMethods, depth, result, from, to)
    if from
      c = from.class
    else
      c= to.class
    end
    f = diffMethods.preMethods[c]
    f.call(depth, result, from, to) if f
  end

  def runPostDiff(diffMethods, depth, result, from, to)
    if from
      c = from.class
    else
      c= to.class
    end
    f = diffMethods.postMethods[c]
    f.call(depth, result, from, to) if f
  end

  def nodeBranchDiff(depth, result, from, to, diffMethods)
    if depth > 0
      magnitude = compareFromTo(from, to)
    else # at depth==0, pretend they are the same.
      magnitude = 0
    end

    if magnitude < 0
      diffMethods.addedBranch(depth, result, to)
    elsif magnitude > 0
      diffMethods.removedBranch(depth, result, from)
    else # magnitude == 0
      diffMethods.inBothBranches(depth, result, from, to)
    end

    # this is a node branch
    fromItems = []
    toItems = []
    fromItems = from.values.sort {|a,b| a.name<=>b.name} if from
    toItems = to.values.sort {|a,b| a.name<=>b.name} if to

    # apply filter from diffMethods against the arrays
    fromItems = filter(fromItems, diffMethods)
    toItems = filter(toItems, diffMethods)

    while fromItems!=[] and toItems!=[]
      fromItem = fromItems.first
      toItem = toItems.first
      magnitude = compareFromTo(fromItem, toItem)
      if magnitude > 0
        toItems.shift
        newresult = result[toItem.name]
        difference(depth+1, newresult, nil, toItem, diffMethods)
      elsif magnitude < 0
        fromItems.shift
        newresult = result[fromItem.name]
        difference(depth+1, newresult, fromItem, nil, diffMethods)
      else # magnitude == 0
        toItems.shift
        fromItems.shift
        newresult = result[fromItem.name]
        difference(depth+1, newresult, fromItem, toItem, diffMethods)
      end
    end
    while fromItems and fromItems!=[]
      item = fromItems.shift
      newresult = result[item.name]
      difference(depth+1, newresult, item, nil, diffMethods)
    end
    while toItems and toItems!=[]
      item = toItems.shift
      newresult = result[item.name]
      difference(depth+1, newresult, nil, item, diffMethods)
    end
  end

  # returns -1 (from<to), 1 (to<from), or 0 (to==from)
  def compareFromTo(from, to)
    if from==nil
      raise "Both 'from' and 'to' are nil" if to==nil
      return -1
    elsif to==nil
      return 1
    elsif from.name<to.name
      return -1
    elsif to.name<from.name
      return 1
    else
      return 0
    end
  end

  def match?
    true
  end
end


class ArrayWalker
  def initialize(origArray, newArray)
    @origArray = origArray
    @newArray = newArray
  end

  def walk
    while @origArray!=[] and @newArray!=[]
      orig = @origArray.first
      new = @newArray.first
      if orig < new
        removed(orig)
        @origArray.shift
      elsif new < orig
        added(new)
        @newArray.shift
      else
        inBoth(orig, new)
        @origArray.shift
        @newArray.shift
      end
    end
    @origArray.each {|item| removed(item)}
    @newArray.each {|item| added(item)}
    finish
  end

  def added(newItem)
  end
  def removed(origItem)
  end
  def inBoth(origItem, newItem)
  end
  def finish
  end
end

class PrintArrayWalker < ArrayWalker
  def added(newItem)
    puts "added #{newItem}"
  end
  def removed(origItem)
    puts "removed #{origItem}"
  end
  def inBoth(origItem, newItem)
    puts "in both #{origItem}, #{newItem}"
  end
  def finish
    puts "all done"
  end
end

# x = PrintArrayWalker.new([1,3,5,7], [3,4,6])
# x.walk


class DepthDifferences
  attr_accessor :classFilters, :preMethods, :postMethods

  def initialize
    @classFilters = {}
    @preMethods = {}
    @postMethods = {}
  end
  def addFilter(aClass, aMethod)
    @classFilters[aClass] = aMethod
  end
  def added(depth, result, newItem)
  end
  def removed(depth, result, origItem)
  end
  def inBoth(depth, result, fromItem, toItem)
  end
  def addedBranch(depth, result, branch)
  end
  def removedBranch(depth, result, branch)
  end
  def inBothBranches(depth, result, fromBranch, toBranch)
  end
  def finish
  end
end

class PrintDiffs < DepthDifferences
  def added(depth, result, newItem)
    puts "added #{newItem.name}" if $VerboseDebugging
  end
  def removed(depth, result, origItem)
    puts "removed #{origItem.name}" if $VerboseDebugging
  end
  def inBoth(depth, result, origItem, newItem)
    puts "inBoth #{newItem.name}" if $VerboseDebugging
  end
  def addedBranch(depth, result, newItem)
    puts "added branch #{newItem.name}" if $VerboseDebugging
  end
  def removedBranch(depth, result, origItem)
    puts "removed branch #{origItem.name}" if $VerboseDebugging
  end
  def inBothBranches(depth, result, origItem, newItem)
    puts "inBoth branch #{newItem.name}" if $VerboseDebugging
  end
end

class PostPartDiffs < PrintDiffs
  def added(depth, result, newItem)
    puts "error -- haven't written PostPartDiffs.added"
    raise "error -- haven't written PostPartDiffs.added"
  end
  def removed(depth, result, origItem)
    puts "error -- haven't written PostPartDiffs.removed"
    raise "error -- haven't written PostPartDiffs.removed"
  end
  def inBoth(depth, result, origItem, newItem)
    super
    result << makeDiffAtom(origItem, newItem)
  end
  def makeDiffAtom(origItem, newItem)
    atom = DataAtom.new
    atom.name = newItem.name
    atom.startTime = 0
    if origItem.dayTotal != 0
      atom.endTime = origItem.dayTotal
    else
      atom.endTime = newItem.dayTotal
    end
    if atom.endTime != 0
      atom.rate = Float(newItem.rateTotal - origItem.rateTotal) / atom.endTime
    else
      puts "oops, no atom.endTime in namedCollection.PostPartDiffs2.makeDiffAtom"
      atom.rate = Float(newItem.rateTotal - origItem.rateTotal)
    end
    return atom
  end
end

class PostPartDiffs2 < PostPartDiffs
  def added(depth, result, newItem)
    puts "error -- haven't written PostPartDiffs.added"
  end
  def removed(depth, result, origItem)
    puts "error -- haven't written PostPartDiffs.removed"
  end
end





class MergePresentationCnC < MergePostMopAnalysis
  def retrieveAnalysisSets(dirSet)
    return dirSet.collect do |dir|
      a=PresentationCnC.new
      a.calculate(dir)
      a.getXMLData
      a
    end
  end

  def makeMopXml(mopset)
    score = Float(mopset.inject(0) {|sum,mop| sum += mop.score.to_f}) / mopset.size
    x = ["<Report>\n",
       "  <metric>#{@name}</metric>\n",
       "  <id>#{@time}</id>\n",
       "  <description>#{@descript}</description>\n",
       "  <score>#{score}</score>\n",
       "  <info><analysis>\n#{makeAnalysisSection(mopset)}\n</analysis></info>\n",
     "</Report>\n"].join("")
    return x
  end # makeMopXml

  def makeAnalysisSection(mopset)
    "<table>\n  <title><column>Run Id</column><column>Score</column><column>Detail</column><column>Exceptions</column></title>\n  " +
       makeAnalysisSectionRows(mopset).join("\n") +
    "</table>\n"
  end

  def makeAnalysisSectionRows(mopset)
    data = []
    mopset.each do |mop|
      data << "  <row><column>#{mop.runid}</column><column>#{mop.score}</column><column>
#{mop.summary}</column><column>
#{mop.exceptions}</column></row>\n"
    end
    return data
  end

  def extractInfo(mopset, analysisStart, analysisEnd)
    m = mopset[0]
    @name = m.name
    @time = "#{Time.now}"
    @descript = m.descript
    lastindex = mopset.size - 1
#    @infos = (0..lastindex).collect {|n| [n+1, mopset[n].date, mopset[n].runid, mopset[n].score, mopset[n].summary]}
    @infos = (0..lastindex).collect {|n| [n+1, mopset[n].runid, mopset[n].score, mopset[n].summary]}
  end
end # class MergePresentationCnC


############################################################################

class PresentationMop
  attr_accessor :runid, :name, :descript, :score, :summary, :exceptions

  def initialize(runid, name, descript, score, summary, exceptions)
    @runid = runid
    @name = name
    @descript = descript
    @score = score
    @summary = summary
    @exceptions = exceptions
  end
end # class PresentationMop


class PresentationCnC
  attr_accessor :runid
  attr_accessor :mops
  attr_accessor :descript, :totalmops
=begin
  attr_accessor :numComplete, :completePopulation
  attr_accessor :numCorrect, :correctPopulation
  attr_accessor :farNumComplete, :farCompletePopulation
  attr_accessor :farNumCorrect, :farCorrectPopulation
  attr_accessor :nearNumComplete, :nearCompletePopulation
  attr_accessor :nearNumCorrect, :nearCorrectPopulation
=end

  def initialize
    super
    reset
    @descript = []
    @transDescript = []
    @totalmops = CompletenessCorrectnessDiffs.new
  end

  def reset
    @numComplete = @completePopulation = 0
    @numCorrect = @correctPopulation = 0

    @farNumComplete = @farCompletePopulation = 0
    @farNumCorrect = @farCorrectPopulation = 0

    @nearNumComplete = @nearCompletePopulation = 0
    @nearNumCorrect = @nearCorrectPopulation = 0
  end

  def nodeNames
    %w(1-AD-NODE  1-BDE-1-AD-NODE  1-CA-BN-NODE  106-TCBN-NODE  2-BDE-1-AD-NODE
       2-CA-BN-NODE  3-BDE-1-AD-NODE  3-CA-BN-NODE  AVNBDE-1-AD-NODE
       NCA  UA-NODE).sort
  end

  def calculate(experimentDir)
    x = nil
    isTransport = nil
    stageName = NoStage
    @descript = []
    @completenessDescript = []
    @correctnessDescript = []
    @farCompletenessDescript = []
    @farCorrectnessDescript = []
    @nearCompletenessDescript = []
    @nearCorrectnessDescript = []
    @runid = experimentDir.split('/')[-1]

    mops = CompletenessCorrectnessDiffs.new
    aggagents = %w(demand_jp8 demand_jp8_ua demand_rate shortfall inventory transport_ad transport_ua basic)
    m = 3 ; n = 5
    aggagents = aggagents[m..n] if $DebugMode
    aggagents.sort.each do |file|
      pattern = /^[io]ba_#{file}_.*xml$/
      # demand_jp8 will pick up demand_jp8_ua unless we restrict it ...
      pattern = /^[io]ba_#{file}_[^u].*xml$/ if file == 'demand_jp8'
      if file =~ /transport/
        isTransport = true
      else
        isTransport = false
      end
      #puts "Reading #{file} AggAgent files, please be patient ..."
      x = loadAggExperiment(experimentDir, "experiment", pattern)
      unless stageName != NoStage
        stageName = x.findStageName
      end
      x.nearTermDivider = getNearTermDividerDay(stageName)
      outBoundsFile = "oba_#{file}_#{stageName}.xml"
      unless x.has_key?(outBoundsFile)
        if file =~ /transport/
          @transDescript << "**********   Out of bounds file #{outBoundsFile} is missing  *********"
        else
          @descript << "**********   Out of bounds file #{outBoundsFile} is missing  *********"
        end
      end
      mops.reset
      nodeNames.each do |nodeName|
        inBoundsFile = "iba_#{file}_#{stageName}_#{nodeName}.xml"
        unless x.has_key?(inBoundsFile)
          if isTransport
            @transDescript << "#{inBoundsFile} was missing"
          else
            @descript << "#{inBoundsFile} was missing"
          end
          next   # probably an assessment problem, and we shouldn't count against society
        end
        x[outBoundsFile].diff(x[inBoundsFile], mops)
        # puts mops
      end
      puts if $VerboseDebugging
      puts "For the #{file} set:  #{mops}" if $VerboseDebugging
      puts if $VerboseDebugging
      if isTransport
        @transDescript += x.exceptionFiles if x.exceptionFiles != []
      else
        @descript += x.exceptionFiles if x.exceptionFiles != []
      end

      addMops(mops)
      # puts "totalmops: #{totalmops}"
      if isTransport
        @farCompletenessDescript << "#{file}: #{mops.farNumComplete}/#{mops.farCompletePopulation}"
        @farCorrectnessDescript << "#{file}: #{mops.farNumCorrect}/#{mops.farCorrectPopulation}"
        @nearCompletenessDescript << "#{file}: #{mops.nearNumComplete}/#{mops.nearCompletePopulation}"
        @nearCorrectnessDescript << "#{file}: #{mops.nearNumCorrect}/#{mops.nearCorrectPopulation}"
      else
        @completenessDescript << "#{file}: #{mops.numComplete}/#{mops.completePopulation}"
        @correctnessDescript << "#{file}: #{mops.numCorrect}/#{mops.correctPopulation}"
      end
    end
    @completenessDescript.unshift "total: #{totalmops.numComplete}/#{totalmops.completePopulation}"
    @correctnessDescript.unshift "total: #{totalmops.numCorrect}/#{totalmops.correctPopulation}"

    @farCompletenessDescript.unshift "total: #{totalmops.farNumComplete}/#{totalmops.farCompletePopulation}"
    @farCorrectnessDescript.unshift "total: #{totalmops.farNumCorrect}/#{totalmops.farCorrectPopulation}"

    @nearCompletenessDescript.unshift "total: #{totalmops.nearNumComplete}/#{totalmops.nearCompletePopulation}"
    @nearCorrectnessDescript.unshift "total: #{totalmops.nearNumCorrect}/#{totalmops.nearCorrectPopulation}"

    @completenessDescript.unshift "completeness mop = #{totalmops.completenessMop}"
    @correctnessDescript.unshift "correctness mop = #{totalmops.correctnessMop}"

    @farCompletenessDescript.unshift "completeness mop = #{totalmops.farCompletenessMop}"
    @farCorrectnessDescript.unshift "correctness mop = #{totalmops.farCorrectnessMop}"

    @nearCompletenessDescript.unshift "completeness mop = #{totalmops.nearCompletenessMop}"
    @nearCorrectnessDescript.unshift "correctness mop = #{totalmops.nearCorrectnessMop}"
  end

  def getNearTermDividerDay(stageName)
    if stageName == "Stage1"
      return 25  # 11
    elsif stageName == "Stage2"
      return 21  # 7
    else
      return 20  # 6
    end
  end


  def getMoeValues
    {
     "correct_present_trans_near" => totalmops.nearCorrectnessMop.to_f,
     "correct_present_trans_far"  => totalmops.farCorrectnessMop.to_f,
     "correct_present_supply"     => totalmops.correctnessMop.to_f,

     "complete_present_trans_near" => totalmops.nearCompletenessMop.to_f,
     "complete_present_trans_far"  => totalmops.farCompletenessMop.to_f,
     "complete_present_supply"     => totalmops.completenessMop.to_f
    }
  end

  def getXMLData
    completeness = makeDescriptSection(@completenessDescript)
    correctness = makeDescriptSection(@correctnessDescript)
    nearCompleteness = makeDescriptSection(@nearCompletenessDescript)
    nearCorrectness = makeDescriptSection(@nearCorrectnessDescript)
    farCompleteness = makeDescriptSection(@farCompletenessDescript)
    farCorrectness = makeDescriptSection(@farCorrectnessDescript)
    exceptionstitle = '<title><column>Exceptions</column></title>'
    exceptions = makeDescriptSection(@descript, exceptionstitle)
    toexceptions = makeDescriptSection(['same as MOP 1-3-2'], exceptionstitle)
    transExceptions = makeDescriptSection(@transDescript, exceptionstitle)
    totransexceptions = makeDescriptSection(['same as MOP 1-3-1-1'], exceptionstitle)

    @mops = [[]]
    x = makeReportSection("1-3-1-1", "Completeness of information collected for presentation - Near-term Transport plan elements",
               totalmops.nearCompletenessMop, nearCompleteness, transExceptions) +
        makeReportSection("1-3-1-2", "Completeness of information collected for presentation - Far-term Transport plan elements",
               totalmops.farCompletenessMop, farCompleteness, totransexceptions) +
        makeReportSection("1-3-2", "Completeness of information collected for presentation - Supply plan elements",
               totalmops.completenessMop, completeness, exceptions) +

        makeReportSection("1-4-1-1", "Correctness of information collected for presentation - Near-term Transport plan elements",
               totalmops.nearCorrectnessMop, nearCorrectness, totransexceptions) +
        makeReportSection("1-4-1-2", "Correctness of information collected for presentation - Far-term Transport plan elements",
               totalmops.farCorrectnessMop, farCorrectness, totransexceptions) +
        makeReportSection("1-4-2", "Correctness of information collected for presentation - Supply plan elements",
               totalmops.correctnessMop, correctness, toexceptions)
    return x
  end

  def makeDescriptSection(descript, title='<title><column>Details</column></title>')
    return "<table>
  #{title}
  <row><column>" + descript.join("</column></row>\n  <row><column>") +
  "</column></row>\n</table>"
  end

  def makeReportSection(name, descript, score, xml, exceptions)
    @mops << PresentationMop.new(@runid, name, descript, score, xml, exceptions)
    exceptions = '' unless exceptions

    x = "<Report>
<metric>MOP #{name}</metric>
<id>#{Time.now}</id>
<description>#{descript}</description>
<score>#{score}</score>
<info><analysis>
#{xml}
#{exceptions}
</analysis></info>
</Report>
"
  end

  def addMops(mops)
    totalmops.numComplete += mops.numComplete
    totalmops.completePopulation += mops.completePopulation
    totalmops.numCorrect += mops.numCorrect
    totalmops.correctPopulation += mops.correctPopulation

    totalmops.farNumComplete += mops.farNumComplete
    totalmops.farCompletePopulation += mops.farCompletePopulation
    totalmops.farNumCorrect += mops.farNumCorrect
    totalmops.farCorrectPopulation += mops.farCorrectPopulation

    totalmops.nearNumComplete += mops.nearNumComplete
    totalmops.nearCompletePopulation += mops.nearCompletePopulation
    totalmops.nearNumCorrect += mops.nearNumCorrect
    totalmops.nearCorrectPopulation += mops.nearCorrectPopulation
  end

=begin
  def completenessMop
    if @completePopulation==0
      return "0.0  Answer is suspect because there was no data to draw from"
    else
      return (@numComplete*100.0) / @completePopulation
    end
  end
  def correctnessMop
    if @correctPopulation==0
      return "0.0  Answer is suspect because there was no data to draw from"
    else
      return (@numCorrect*100.0) / @correctPopulation
    end
  end
=end
end # class PresentationCnC

class CompletenessCorrectnessDiffs < DepthDifferences
  attr_accessor :numComplete, :completePopulation
  attr_accessor :numCorrect, :correctPopulation
  attr_accessor :farNumComplete, :farCompletePopulation
  attr_accessor :farNumCorrect, :farCorrectPopulation
  attr_accessor :nearNumComplete, :nearCompletePopulation
  attr_accessor :nearNumCorrect, :nearCorrectPopulation

  def initialize
    super
    reset
  end

  def reset
    @numComplete = @completePopulation = 0
    @numCorrect = @correctPopulation = 0
    @farNumComplete = @farCompletePopulation = 0
    @farNumCorrect = @farCorrectPopulation = 0
    @nearNumComplete = @nearCompletePopulation = 0
    @nearNumCorrect = @nearCorrectPopulation = 0
  end

  def to_s
    "complete: #{numComplete}/#{completePopulation}, correct: #{numCorrect}/#{correctPopulation}, farcomplete: #{farNumComplete}/#{farCompletePopulation}, correct: #{farNumCorrect}/#{farCorrectPopulation}, nearcomplete: #{nearNumComplete}/#{nearCompletePopulation}, correct: #{nearNumCorrect}/#{nearCorrectPopulation}"
  end

  def added(depth, result, newItem)
    # additional data does not count against (or for) completeness or correctness.
    # do nothing
  end

  def removed(depth, result, removedItem)
    removedItem.each do |item|
      #item.days.times do
        itemNotComplete(item, result)
      #end
    end
  end

  def inBoth(depth, result, origItem, newItem)
    origatoms = origItem.children.sort
    newatoms = newItem.children.sort
    while origatoms!=[] and newatoms!=[]
      orig = origatoms.first
      new = newatoms.first
      if orig < new      # removed
        itemNotComplete(orig, result)
        origatoms.shift
      elsif new < orig   # added
        # do nothing    itemNotComplete(orig, result)
        newatoms.shift
      else
        itemComplete(orig, result)
        if orig.transport?
          if (orig.startTime == new.startTime) and (orig.endTime == new.endTime)
            itemCorrect(orig, result)
          else
            itemNotCorrect(orig, result)
          end
        else
          if (orig.rate == new.rate)
            itemCorrect(orig, result)
          else
            itemNotCorrect(orig, result)
          end
        end
        origatoms.shift
        newatoms.shift
      end
    end
    origatoms.each do |item|
      itemNotComplete(item, result)
    end
    # additional items don't count against the score
    #newatoms.each do |item|
    #  itemComplete(item, result)
    #  notCorrect
    #end
  end

  def itemComplete(item, parent)
    if item.transport?
      if item.nearTerm?(parent)
        nearComplete
      else
        farComplete
      end
    else  # supply
      complete
    end
  end
  def itemNotComplete(item, parent)
    if item.transport?
      if item.nearTerm?(parent)
        nearNotComplete
      else
        farNotComplete
      end
    else  # supply
      notComplete
    end
  end

  def itemCorrect(item, parent)
    if item.transport?
      if item.nearTerm?(parent)
        nearCorrect
      else
        farCorrect
      end
    else  # supply
      correct
    end
  end
  def itemNotCorrect(item, parent)
    if item.transport?
      if item.nearTerm?(parent)
        nearNotCorrect
      else
        farNotCorrect
      end
    else  # supply
      notCorrect
    end
  end

  def complete
    @numComplete+=1
    @completePopulation+=1
  end
  def notComplete
    @completePopulation+=1
  end
  def farComplete
    @farNumComplete+=1
    @farCompletePopulation+=1
  end
  def farNotComplete
    @farCompletePopulation+=1
  end
  def nearComplete
    @nearNumComplete+=1
    @nearCompletePopulation+=1
  end
  def nearNotComplete
    @nearCompletePopulation+=1
  end

  def correct
    @numCorrect+=1
    @correctPopulation+=1
  end
  def notCorrect
    @correctPopulation+=1
  end
  def farCorrect
    @farNumCorrect+=1
    @farCorrectPopulation+=1
  end
  def farNotCorrect
    @farCorrectPopulation+=1
  end
  def nearCorrect
    @nearNumCorrect+=1
    @nearCorrectPopulation+=1
  end
  def nearNotCorrect
    @nearCorrectPopulation+=1
  end

  def completenessMop
    mopAux(@numComplete, @completePopulation)
  end
  def correctnessMop
    mopAux(@numCorrect, @correctPopulation)
  end
  def nearCompletenessMop
    mopAux(@nearNumComplete, @nearCompletePopulation)
  end
  def nearCorrectnessMop
    mopAux(@nearNumCorrect, @nearCorrectPopulation)
  end
  def farCompletenessMop
    mopAux(@farNumComplete, @farCompletePopulation)
  end
  def farCorrectnessMop
    mopAux(@farNumCorrect, @farCorrectPopulation)
  end

  def mopAux(numerator, denominator)
    if denominator==0
      return "0.0  (see details)"
    else
      return (numerator*100.0) / denominator
    end
  end
end

class NamedArray <NamedHash
   def initialize(name='noname')
      super(name)
      setName(name)
      @children = []
   end
   def to_ss
     "#{self.class.name} #{name}, parent=#{parent.name}, <<#{children.each_value {|child| child.to_s}.join(', ')}>>"
   end
   def size
     @children.size
   end
   def [](n)
     @children[n]
   end
   def each(&block)
      @children.each do |atom|
#         block atom  , @children[atom]
         yield atom
      end
   end
   def self.defaultSubsequenceClass
      return Array
   end
   def self.defaultSubsequence(key)
      return defaultSubsequenceClass.new
   end
   def sort
      @children.sort! {|a, b| a.startTime <=> b.startTime}
   end
end
class NamedSummer <NamedArray
   def sum
      total = 0
      @children.each {|x| total = total + x}
      total
   end
end
