#!/usr/bin/env ruby

require 'security/lib/doIrb'


startingScript = $0.split('/')[-1]
runningThisFile = startingScript == 'securityMopAnalysis.rb'

if runningThisFile
  # remove when done
  CIP=ENV['CIP']
  $LOAD_PATH.unshift "#{CIP}/csmart/acme_scripting/src/lib"
  $LOAD_PATH.unshift "#{CIP}/csmart/acme_service/src/redist"
  $LOAD_PATH.unshift "../.."
  require 'security/lib/scripting'
  require 'security/lib/logisticsMop/scripting'
end


require 'pstore'
#require 'security/lib/logisticsMop/scripting'

MopNamesInDb = %w(blank memory_data disk_data transmission_data
    illegal_user_actions record_user_actions record_user_violations)


TcpCaptureResult = Struct.new(:tuples, :numEncrypted, :numNotEncrypted)

class Mop2_3Tuple
  attr_accessor :name, :files, :encryptedFiles, :synFiles

  def initialize(name)
    @name = name
    @files = []
    @encryptedFiles = []
    @synFiles = []
  end
end





class PostSecurityMopAnalysis
  attr_accessor :dir, :runid, :datestring, :date, :html, :scores, :origScores, :raw, :mops

  def initialize(dir)
    @dir = dir
    match = dir.scan(/\/([0-9]*)\//)
    @runid = 'unknown'
    @runid = match[0][0] if match and match!=[]
    preprocess(dir)
  end

  def getMoeValues
    scores = @scores
    # comment next line if don't want to convert via MOE 2 charts in
    # survivability document.
    moeValues = {}
    1.upto(6) do |n|
      moeValues["#{MopNamesInDb[n]}"] = scores[n]
    end
    return moeValues
  end

  def getXMLData
    getMopData
    xml = ''
    1.upto(6) do |n|
     begin
        @mops[n].score = @scores[n]
        @mops[n].summary = @summary[n]
        @mops[n].date = @date
        @mops[n].runid = runid
        xml += makeMopXml(@mops[n])
      rescue Exception => e
        puts "error #{e.message}"
        puts e.backtrace.join("\n")
      end
    end
    return xml
  end

############  End Amit  #####################


  def makeMopXml(mop)
    x = "<Report>\n"
    x +=  "<metric>MOP #{mop.name}</metric>\n"
    x +=  "<id>#{Time.now}</id>\n"
    x +=  "<description>#{mop.descript}</description>\n"
    x +=  "<score>#{mop.scoreText}</score>\n"
    #x +=  "<info><analysis><para>#{mop.info}</para></analysis></info>\n"
    x +=  "<info><analysis><para>#{mop.summary}</para></analysis></info>\n"
    x +="</Report>\n"
    return x
  end # makeMopXml

=begin
# if this section is uncommented, add in:
#   require 'security/lib/logisticsMop/mauBaseline'
#   require 'security/lib/logisticsMop/mauCharts'
  def convertScores  #(scores)
    charts = []
    1.upto(3) {|n| charts << MauChart.getChart("security2loose")}
    1.upto(3) {|n| charts << MauChart.getChart("security2strict")}
    charts.unshift nil
    newScores = [nil]
    1.upto(6) {|n| newScores << charts[n].mau(@origScores[n])}
    @scores = newScores
    newScores
  end
=end

  def getMopData
    @mops = [nil, SecurityMop21.new, SecurityMop22.new,
                 SecurityMop23.new, SecurityMop24.new,
                 SecurityMop25.new, SecurityMop26.new]
    @mops = @mops.collect {|m| m.dup if m}
    getXMLDataForMop1
    getXMLDataForMop2
    3.upto(6) do |n|
      getXMLDataForMop(n)
    end
  end

  def getXMLDataForMop1

    @mops[1].info = ''
  end

  def getXMLDataForMop2
    answer = []
    raw[2].collect do |a|

      answer << "agent: #{a[0]}, file: #{a[1]}, #{a[2]}"
    end
    @mops[2].info = answer.join("<br/>\n")
  end

  def getXMLDataForMop(mopNum)
    @mops[mopNum].info = raw[mopNum].join("<br/>\n")
    return @mops[mopNum].info
  end

  def preprocess(dirname)
    begin
      load(dirname) 
    rescue Exception => e
      logInfoMsg "Couldn't load mop data from #{dirname}"
    end
    loadTcpCapture(dirname)
    analyzeTcpCapture(dirname)
  end

  def load(dirname)
    @origScores = Array.new(7)  # in case an error is raised
    @raw = Array.new(7)
    
    filename = "#{dirname}/mops"
    db = PStore.new(filename)
    db.transaction do |db|
      # puts db.roots.inspect
      @datestring = db['datestring']
      @date = db['date']
      @html = db['html']      # this is a string
      @scores = db['scores']
      @raw = db['raw']
      @summary = db['summary']
    end # db.transaction
    # make so we can index beginning at 1.
    @scores.unshift nil
    # MOPs 2-1 thru 2-4 are expressed in negative terms.
    1.upto(4) {|n| @scores[n] = Float(100.0 - @scores[n])}
    @origScores = @scores.dup
    @raw.unshift nil
    @summary.unshift nil
    @summary[5] = switchem(@summary[5], 'There were ', ' servlet access attempts, ', ' were correct.')
    @summary[6] = switchem(@summary[6], 'There were ', ' servlet access attempts, ', ' were correct.')
  end

  def switchem(text, before, middle, after)
    pattern = /#{before}([^ ]*)#{middle}([^ ]*)/
    match = text.scan(pattern)
    if match
      return before + match[0][1] + middle + match[0][0] + after
    else
      return text
    end
  end
  # puts switchem('There were 5 servlet access attempts, 10 were correct', 'There were ', ' servlet access attempts, ', ' were correct.')
  # puts switchem('There were  servlet access attempts,  were correct', 'There were ', ' servlet access attempts, ', ' were correct.')

  def analyzeTcpCapture(dirname)
    @numEncrypted = @numFiles = @numIgnored = 0
    @raw[3] = []
    @tupleFiles.each do |filename, tuples| 
      # if a tuple has
      tuples.each do |agentname, tuple|
        if tuple.synFiles.empty?
          @numIgnored += tuple.files.size
        else
          @numFiles += tuple.files.size
          @numEncrypted += tuple.files.size unless tuple.encryptedFiles.empty?
        end
      end
#puts "#{@numIgnored}, #{@numEncrypted}, #{@numFiles}"
      msg = "host: #{filename} encrypted: #{@numEncrypted}, total: #{@numFiles}, ignored: #{@numIgnored}"
      @raw[3] << msg
    end
    if @numFiles > 0
      score = (@numEncrypted.to_f / @numFiles.to_f) * 100.0
      @summary[3] = "#{@numEncrypted} files were encrypted out of #{@numFiles} files."
    else
      score = 100.0
      @summary[3] = "There weren't any tcp capture files."
    end
    @scores[3] = Float(100.0 - score) # mop is stated in the negative
    @origScores[3] = @scores[3]
  end

  def loadTcpCapture(dirname)
    files = Dir.entries(dirname)
    files = files.select {|f| f =~ /tcplog$/}
    tcps = []
    @tupleFiles = {}
    files.sort.each do |filename|
      db = PStore.new("#{dirname}/#{filename}")
      db.transaction do |db|
        @tupleFiles[filename] = db['tuples']
      end
    end
    nil
  end
end



if runningThisFile
  dir = "../../scripts03/mops5"
  dir = "#{ENV['CIP']}/workspace/security/mops"

  a = PostSecurityMopAnalysis.new(dir)

  puts a.getXMLData
  puts "---------------"
  puts a.getScores
end


=begin
puts 'hi'
1.upto(6) do |n|
  puts "#{n}: #{a.raw[n].size}, #{a.raw[n].class}"
end

if false
  1.upto(6) do |n|
    puts '************************************************'
    puts a.html[n]
    puts "above was 2-#{n}"
    STDIN.gets
  end
end

puts a.getXMLData

2.upto(6) do |n|
  puts "#{n}: #{a.raw[n][0].class}"
end
puts a.scores.inspect

puts "raw[3]:"
puts a.raw[3].join("\n")

puts 'done'
=end
