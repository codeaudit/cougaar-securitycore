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
