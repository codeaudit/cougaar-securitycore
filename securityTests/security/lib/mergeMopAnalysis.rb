require 'pstore'

class MergePostMopAnalysis
  def initialize(*dirs)
    if true   # calculate results
      @analysisSets = retrieveAnalysisSets(dirs)
      # storeAnalysisSets
    else       # load already calculated results from a file
      loadAnalysisSets
      return
    end
  end

  def storeAnalysisSets
    puts "storing analysisSets"
    db = PStore.new('analysisSets')
    db.transaction do
      db['analysisSets'] = @analysisSets
    end
    puts "  done storing"
  end

  def loadAnalysisSets
    db = PStore.new('analysisSets')
    db.transaction do
      @analysisSets = db['analysisSets']
    end
  end

  def getMoeValues
    scoresSets = @analysisSets.collect do |a|
      a.getMoeValues
    end
    scores = {}
    scoresSets.each do |set|
      set.each_key do |key|
        scores[key] = 0.0 unless scores.has_key?(key)
        scores[key] += set[key].to_f
      end
    end
    scores.each_key {|key| scores[key] = Float(scores[key]) / scoresSets.size}
    return scores
  end

  def getXMLData(analysisStart='<para>', analysisEnd='</para>')
    transformAnalysisByMopNumber
    xml = []
    @mops.each do |mopset|
      unless mopset == []
        extractInfo(mopset, analysisStart, analysisEnd)
        result = makeMopXml(mopset)
        xml << result
      end
    end
    return xml.join("\n")
  end

  def transformAnalysisByMopNumber
    # collect all of mop 2.1 into mops[1], mop 2.2 into mops[2], ...
    # (transform, as in matrix transform)
    numMops = @analysisSets[0].mops.size
    @mops = (1..numMops).collect {|ignore| []}
    @analysisSets.each do |analysis|
      0.upto(numMops-1) do |n|
        @mops[n] << analysis.mops[n] if analysis.mops[n]
      end
    end
    @mops = @mops.collect do |mopset|
      mopset.select {|mop| mop and mop!=[]}
    end
  end

  def extractInfo(mopset, analysisStart, analysisEnd)
  end
  def makeMopXml(mopset)
    puts "extractInfo is subclass's responsibility"
  end
end



class MergePostSecurityMopAnalysis < MergePostMopAnalysis
  def retrieveAnalysisSets(dirSet)
    @analysisSets = dirSet.collect do |dir|
      a=PostSecurityMopAnalysis.new(dir)
      a.getXMLData
      a
    end
  end

  def extractInfo(mopset, analysisStart, analysisEnd)
    m = mopset[0]
    @name = m.name
    @time = "#{Time.now}"
    @descript = m.descript
    lastindex = mopset.size - 1
    @infos = (0..lastindex).collect {|n| [n+1, mopset[n].date, mopset[n].runid, mopset[n].score, mopset[n].summary]}
  end

  def makeMopXml(mopset)
    score = Float(mopset.inject(0) {|sum,mop| sum += mop.score}) / mopset.size
    x = "<Report>\n"
    x +=  "<metric>#{@name}</metric>\n"
    x +=  "<id>#{@time}</id>\n"
    x +=  "<description>#{@descript}</description>\n"
    x +=  "<score>#{score}</score>\n"
    x +=  "<info><analysis>#{makeAnalysisSection}</analysis></info>\n"
    x +="</Report>\n"
    return x
  end # makeMopXml

  def makeAnalysisSection
    "<table>\n  <title><column>Run Id</column><column>Date</column><column>Score</column><column>Detail</column></title>\n  " +
       makeAnalysisSectionRows.join("\n") +
    "</table>\n"
  end

  def makeAnalysisSectionRows
    data = []
    @infos.each do |info|
      data << "  <row><column>#{info[2]}</column><column>#{info[1]}</column><column>#{info[3]}</column><column>#{info[4]}</column></row>"
    end
    return data
  end

=begin
  def getAnalysisSections(mop, analysisStart, analysisEnd)
    @paras = mop.collect {|m| pulltext(m, analysisStart, analysisEnd)}
  end

  def postGetAnalysisSections
    # can use this to add <table> sections in a subclass
  end
  def addTableSectionsExample
    @paras = @paras.collect {|p| "<table><row>#{p}</row></table>"}
  end

  def pulltext(text, before, after, stoptext='.*')
    return '' unless text
    pattern = /#{before}(#{stoptext})#{after}/
    match = text.scan(pattern)
    return '' unless match
    return match[0][0]
  end
  # puts pulltext('<asdf>defghi<f></asdf>', '<asdf>', '</asdf>')
=end
end
