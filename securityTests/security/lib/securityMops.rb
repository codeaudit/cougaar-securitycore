require 'security/lib/AbstractSecurityMop'

snortDir = "#{ENV['CIP']}/csmart/assessment/lib/security/data"

################################################

Mop2_1 = Struct.new(:agent, :type, :successes, :total)

class SecurityMop21 < AbstractSecurityMop
  attr_accessor :legitsuccesses, :legittotal
  attr_accessor :malicioussuccesses, :malicioustotal

  def initialize(run)
    super(run)
    @name = "2-1"
    @descript = "Percentage of sensitive data elements in computer memory that were available to an unauthorized entity"
    @detail = []
    reset
  end

  def reset
    @legitsuccesses = @legittotal = 0
    @malicioussuccesses = @malicioustotal = 0
  end

  def setup
    #Requires Oplan ready
    @nextAgent = nil
    begin
      @run.society.each_agent(true) do |agent|
        @nextAgent = agent
#        url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testBlackboardManager?do=start&exp=#{@run.name}"
        url = "#{agent.uri}/testBlackboardManager?do=start&exp=#{@run.name}"
        result = Cougaar::Communications::HTTP.get(url)
        #puts "result #{result}" if $VerboseDebugging
      end
    rescue Exception => e
      if @nextAgent.kind_of?(Agent)
        puts "ERROR: Could not activate testBlackboardManager on #{@nextAgent.name}"
      else
        puts "ERROR: Could not activate testBlackboardManager on #{@nextAgent.class}"
      end
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
      # raise "Could not activate testBlackboardManager"
    end
  end

  def perform
    # do nothing
  end

  def shutdown
    begin
      run.society.each_agent(true) do |agent|
        url ="http://#{agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testBlackboardManager?do=end&exp=#{run.name}"
#        url ="#{agent.uri}/testBlackboardManager?do=end&exp=#{run.name}"
#        puts "ending testBlackboardManager #{url}" if $VerboseDebugging
        puts url if $VerboseDebugging
        req=Cougaar::Communications::HTTP.get(url)
        #puts "mop 2.1 end #{agent.name}, #{url}, #{req}" if $VerboseDebugging
      end #end each agent
    rescue Exception => e
      puts "ERRR: Could not stop testBlackboardManager"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
    # sleep so the agents can save the results to the files
    sleep 1.minutes
  end

  def calculate
    begin
      @score = compileResults
      puts "compiledResults #{@score}" if $VerboseDebugging
      @info = "MOP 2.1 (Blackboard access control): #{@score} - Legitimate successful tries: #{@legitsuccesses} / #{@legittotal}, malicious: #{@malicioussuccesses} / #{@malicioustotal}<br\>\n" + @info.join("<br/>\n")
      @calculationDone = true
      sucess = false
      if (@score == 100.0)
	success = true
      end
      saveResult(success, 'mop2.1',@info)

    rescue Exception => e
puts "error, probably in compileResults" if $VerboseDebugging
      puts "error in #{self.class.name}.calculate"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
  end

  def compileResults
    mop = 0.0
    @legitsuccesses = @legittotal = @malicioussuccesses = @malicioustotal = 0
    expname=run.name
    @raw = []
    @info = []
    resultsdirectory = "#{ENV['COUGAAR_INSTALL_PATH']}/workspace/security/mopresults"
    files = Dir["#{resultsdirectory}/*csv"]
    files.each do |file|
      puts "Filename:#{file}" if $VerboseDebugging
      lines= File.readlines(file)
      cols = lines[1].split(',')
      successes = cols[3].to_i
      failures = cols[4].to_i
      total = cols[5].to_i
      agent = cols[6]
      plugin = cols[7]

      if plugin =~ /Malicious/i
        type = "malicious"
        @malicioussuccesses += successes
        @malicioustotal += total
      elsif plugin =~ /Legitimate/i
        type = "legit"
        @legitsuccesses += successes
        @legittotal += total
      else
	raise "Unexpected plugin type: #{plugin}"
      end

      s = "#{type} plugin on #{agent}: #{successes} successes / #{failures} failures, #{total} total"
      puts s if $VerboseDebugging
      @info.push(s)
      #@raw.push([agent, type, successes, total])
      @raw.push(Mop2_1.new(agent, type, successes, total))
    end # looping through files


    totalruns = @legittotal + @malicioustotal
    totalsuccesses = @legitsuccesses + @malicioussuccesses
    if totalruns != 0
      mop = 100 * (totalsuccesses.to_f / totalruns.to_f)
      @summary = "Legitimate: #{@legitsuccesses} correct of out #{@legittotal}. Malicious: #{@malicioussuccesses} correct out of #{@malicioustotal}.  #{mop}% correct."
    else
      mop = 100.0
      @summary = "There weren't any blackboard access attempts made, so 0% of the (non-existent) attempts were accessible to an unauthorized entity."
    end
    puts @summary if $VerboseDebugging
    return mop
  end #compile results

  def scoreText
    if @summary =~ /^There weren/
      return noScore
    else
      return @score
    end
  end
end # SecurityMop2_1

class SecurityMop2_1 < SecurityMop21
  include Singleton
end


################################################

class SecurityMop22 < AbstractSecurityMop
  def initialize(run)
    super(run)
    @name = "2-2"
    @descript = "Percentage of sensitive data elements stored on disk that were available to an unauthorized entity"
  end

  def calculate
    d = DataProtection.new
    @score = d.checkDataEncrypted("cougaar", 8000, false)
    @summary = d.summary
    @raw = d.filelist
    @info = d.mopHtml
    @calculationDone = true

    sucess = false
    if (@score == 100.0)
      success = true
    end
    saveResult(success, 'mop2.2', @info)
  end

  def scoreText
    begin
      match = @summary.scan(/in ([^ ]*) persisted/)
      if match
        size = match[0][0].to_i
        if size == 0
          return noScore
        else
          return @score
        end
      end
    rescue Exception => e
      return @score
    end
  end
end

class SecurityMop2_2 < SecurityMop22
  include Singleton
end
    
################################################

class SecurityMop23 < AbstractSecurityMop
  def initialize(run)
    super(run)
    @name = "2-3"
    @descript = "Percentage of sensitive data elements transmitted between computers that were available to an unauthorized entity"
  end

  def scoreText
    if @summary =~ /^There weren/
      return noScore
    else
      return @score
    end
  end

  def startTcpCapture(agentnames)
    # executable attribute not set when first unzipped.
    %w(runsnort runsnort-aux analyzesnort analyzesnort-aux).each do |file|
      f = "#{ENV['CIP']}/csmart/assessment/lib/lib/#{file}"
      `chmod a+x #{f}`
    end
    hosts = []
    agentnames.each do |agentname|
      if agentname.kind_of?(String)
        agent = getRun.society.agents[agentname]
      else
        agent = agentname
      end
      if agent
        hosts << agent.host
      else
        logInfoMsg "Agent #{agentname} is not in the society, so no TCP capture will occur."
      end
    end
    @hosts = hosts.uniq

    puts "Starting TCP capture on hosts #{@hosts.collect {|h| h.name}.sort.inspect}" if $VerboseDebugging

    @hosts.each do |host|
      doRemoteCmd(host.name, "#{snortDir}/runsnort #{ENV['CIP']}")
    end
  end

  def shutdown
    stopTcpCapture
  end

  def stopTcpCapture
    return unless @hosts
    logInfoMsg (@hosts.collect {|h| h.name}).sort if $VerboseDebugging
    @hosts.each do |host|
      doRemoteCmd(host.name, "#{snortDir}/analyzesnort #{ENV['CIP']}")
    end
  end

  def calculationDone
    lognames = @hosts.collect {|host| "#{host.name}.tcplog"}
    dirfiles = Dir.entries(SecurityMopDir)
    missing = lognames - dirfiles
    puts "missing files: #{missing.inspect}" if $VerboseDebugging and missing!=[]
    return missing == []
  end

  def calculate
    @score = 100.0
    @raw = []
    @info = ''
  end
end
    
class SecurityMop2_3 < SecurityMop23
  include Singleton
end

################################################


def doRemoteCmd(hostname, cmd, timeout=30)
  if hostname.kind_of?(String)
    host = getRun.society.hosts[hostname]
  else
    host = hostname
  end
  cmd = "command[rexec]#{cmd}"
  logInfoMsg "doRemoteCmd: #{hostname}, #{cmd}" if $VerboseDebugging
  begin
    answer = getRun.comms.new_message(host).set_body(cmd).request(timeout)
    logInfoMsg "doRemoteCmd answer #{hostname}: #{answer.class}, #{answer}" if $VerboseDebugging
    if answer
      return getRexecBody(answer.to_s).chomp
    else
      return nil
    end
  rescue Exception => e
    backtrace = e.backtrace.join("\n")
    raise "Error in doRemoteCmd, host: #{hostname}, cmd: #{cmd}\n#{e.class}, #{e.message}\n#{backtrace}"
  end
end

def getRexecBody(xml)
  answer = xml.scan(/<body>(.*)<\/body>/m)
  return answer[0][0]
end


=begin
require 'rexml/document'
include REXML
def getRexecBody(xml)
  doc = Document.new(xml)
  type = 'error'
  doc.elements.each('message') {|ele| type = ele.attributes['type']}
  raise("Error on remote command.  Remote answer was:  [#{xml}]") if type == 'error'

  answer = ''
  doc.elements.each('message/body') do |ele|
    answer = ele.text.chomp
  end
end
=end