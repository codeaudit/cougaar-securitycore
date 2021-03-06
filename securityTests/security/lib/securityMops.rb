require 'singleton'
require 'security/lib/AbstractSecurityMop'
require 'security/lib/securityMopAnalysis'
require 'security/lib/doIrb'

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

  def getStressIds()
    return ["SecurityMop2.1"]
  end

  def reset
    @legitsuccesses = @legittotal = 0
    @malicioussuccesses = @malicioustotal = 0
  end

  def setup
    #Requires Oplan ready
    @nextAgent = nil
    begin
      @run.society.each_node do |node|
        agent_count = 0
        node.each_agent do |agent|
          if agent_count > 1 then
            break
          end
          agent_count += 1
      
          @nextAgent = agent
          url = "#{agent.uri}/testBlackboardManager?do=start&exp=#{@run.name}"
          result = Cougaar::Communications::HTTP.get(url)
#         puts "result #{result}" # if $VerboseDebugging
        end #each_agent
      end #each_node
    rescue Exception => e
      if @nextAgent.kind_of?(Cougaar::Model::Agent)
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
      run.society.each_node do |node|
        agent_count = 0
        node.each_agent do |agent|
          if agent_count > 1 then
            break
          end
          agent_count += 1

          url ="#{agent.uri}/testBlackboardManager?do=end&exp=#{run.name}"
#         puts "ending testBlackboardManager #{url}" if $VerboseDebugging
          puts url if $VerboseDebugging
          req=Cougaar::Communications::HTTP.get(url)
         #puts "mop 2.1 end #{agent.name}, #{url}, #{req}" if $VerboseDebugging
        end #each_agent
      end #end each node
    rescue Exception => e
      puts "ERROR: Could not stop testBlackboardManager"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
    # sleep so the agents can save the results to the files
    # (this sleep needs to occur elsewhere in parallel with other waits)
#    sleep 1.minutes
  end

  def calculate
    begin
      @score = compileResults
      puts "compiledResults #{@score}" if $VerboseDebugging
      summary = "MOP 2.1 (Blackboard access control): #{@score} - Legitimate successful tries: #{@legitsuccesses} / #{@legittotal}, malicious: #{@malicioussuccesses} / #{@malicioustotal}"
####      @info = "MOP 2.1 (Blackboard access control): #{@score} - Legitimate successful tries: #{@legitsuccesses} / #{@legittotal}, malicious: #{@malicioussuccesses} / #{@malicioustotal}<br/>\n" + @info.join("<br/>\n")
      @isCalculationDone = true
      success = false
      if (@score == 0.0)
	success = true
      end
      saveResult(success, 'SecurityMop2.1', summary)
      saveAssertion('SecurityMop2.1', @info.join("\n"))

    rescue Exception => e
puts "error, probably in compileResults" if $VerboseDebugging
      puts "error in #{self.class.name}.calculate"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
    # Remove tasks from blackboard
    begin
      @run.society.each_node do |node|
        agent_count = 0
        node.each_agent do |agent|
          if agent_count > 1 then
            break
          end
          agent_count += 1
          url = "#{agent.uri}/testBlackboardManager?do=removeTasks&exp=#{@run.name}"
          result = Cougaar::Communications::HTTP.get(url)
          #puts "Remove MOP 2.1 tasks from blackboard on agent #{agent.name}"
        end #each_agent
      end #each_node
    rescue Exception => e
      puts "ERROR: Unable to remove MOP 2.1 tasks"
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

    @supportingData = {'malicioussuccesses'=>@malicioussuccesses, 'malicioustotal'=>@malicioustotal, 'legitsuccesses'=>@legitsuccesses, 'legittotal'=>@legittotal}
    totalruns = @legittotal + @malicioustotal
    totalsuccesses = @legitsuccesses + @malicioussuccesses
    if totalruns != 0
      mop = 100.0 - (100 * (totalsuccesses.to_f / totalruns.to_f))
      @summary = "Legitimate: #{@legitsuccesses} correct of out #{@legittotal}. Malicious: #{@malicioussuccesses} correct out of #{@malicioustotal}.  #{100-mop}% correct."
    else
      mop = 0.0
      @summary = "There weren't any blackboard access attempts made, so 0% of the (non-existent) attempts were accessible to an unauthorized entity."
    end
    puts @summary if $VerboseDebugging
    return mop
  end #compile results

  def scoreText
    # the next line is for data that was stored with 'legitttotal' (3 t's).
    @supportingData['legittotal'] = 0 unless @supportingData['legittotal']
    @supportingData['malicioustotal'] = 0 unless @supportingData['malicioustotal']
    if @supportingData['malicioustotal'] + @supportingData['legittotal'] == 0
#    if @summary =~ /^There weren/
      return noScore
    else
      return @score
    end
  end
end # SecurityMop2_1

=begin
class SecurityMop2_1 < SecurityMop21
  include Singleton
  def initialize
    super(getRun)
  end
end
=end


################################################

class SecurityMop22 < AbstractSecurityMop
  def initialize(run)
    super(run)
    @name = "2-2"
    @descript = "Percentage of sensitive data elements stored on disk that were available to an unauthorized entity"
  end

  def getStressIds()
    return ["SecurityMop2.2"]
  end

  def perform
    # capturing persistent files is part of a normal cougaar run, so do nothing
  end

  def calculate
    d = DataProtection.new
    @score = d.checkDataEncrypted("cougaar", 8000, false)
    @summary = (d.summary)[1]
    @raw = d.filelist
    @info = d.mopHtml
    @supportingData = d.supportingData
    @isCalculationDone = true

    success = false
    if (@score == 0.0)
      success = true
    end
    saveResult(success, 'SecurityMop2.2', d.summary.join("\n"))
    saveAssertion('SecurityMop2.2', @info)
  end

  def scoreText
    begin
      if @supportingData['size'] == 0
        return noScore
      else
        return @score
      end
=begin
      match = @summary.scan(/in ([^ ]*) persisted/)
      if match
        size = match[0][0].to_i
        if size == 0
          return noScore
        else
          return @score
        end
      end
=end
    rescue Exception => e
      return @score
    end
  end
end

=begin
class SecurityMop2_2 < SecurityMop22
  include Singleton
  def initialize
    super(getRun)
  end
end
=end
    
################################################


class SecurityMop23 < AbstractSecurityMop
  def initialize(run)
    super(run)
    @name = "2-3"
    @descript = "Percentage of sensitive data elements transmitted between computers that were available to an unauthorized entity"

    @scriptsdir = File.join(ENV['CIP'], "csmart", "lib", "security", "mop")
    @datadir = File.join(ENV['CIP'], "workspace", "security", "mops")
    @cipuser = `whoami`.chomp
    `mkdir -p #{@datadir}`   # Make parent dirs as needed
    # Dir.mkdirs(@logfilename) unless File.exist?(@logfilename) 
  end

  def getStressIds()
    return ["SecurityMop2.3"]
  end

  def scoreText
    if @supportingData['numFiles'] == 0
#    if @summary =~ /^There weren/
      return noScore
    else
      return @score
    end
  end

  def startTcpCapture(agentnames)
    # executable attribute not set when first unzipped.
    %w(runsnort runsnort-aux analyzesnort analyzesnort-aux).each do |file|
      f = File.join(@scriptsdir, file)
      `chmod a+x #{f}`
    end
    hosts = []
    agentnames.each do |agentname|
      if agentname.kind_of?(String)
        agent = run.society.agents[agentname]
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
    saveAssertion "SecurityMop2.3", "Starting TCP capture on hosts #{@hosts.collect {|h| h.name}.sort.inspect}" 
    
    begin
      @hosts.each do |host|
        doRemoteCmd(host.name, "#{@scriptsdir}/runsnort")
      end
    rescue => ex
      saveAssertion "SecurityMop2.3", "Unable to run snort: #{ex}\n #{ex.backtrace.join("\n")}"
    end
  end

  def shutdown
    stopTcpCapture
  end

  def stopTcpCapture
    return unless @hosts
    logInfoMsg (@hosts.collect {|h| h.name}).sort if $VerboseDebugging
    saveAssertion "SecurityMop2.3", "Stopping TCP capture on hosts #{@hosts.collect {|h| h.name}.sort.inspect}" 
    @hosts.each do |host|
      doRemoteCmd(host.name, "#{@scriptsdir}/analyzesnort #{@datadir} #{@cipuser}")
    end
  end

  def isCalculationDone
    lognames = @hosts.collect {|host| "#{host.name}.tcplog"}
    dirfiles = Dir.entries(SecurityMopDir)
    missing = lognames - dirfiles
    puts "missing files: #{missing.inspect}" if $VerboseDebugging and missing!=[]
    return missing == []
  end

  def calculate
    @score = 999.9
    @raw = []
    @info = ''
  end

  def postCalculate
    begin
      analysis = PostSecurityMopAnalysis.new(@datadir)
      analysis.mops = run['mops']
      @summary = analysis.summary[3]
      @info = analysis.getXMLDataForMop(3)
      @supportingData = analysis.supportingData[3]
      @raw = analysis.raw[3]
      @score = analysis.scores[3]
      saveAssertion "SecurityMop2.3", "postCalculate: #{analysis.scores[3]}\n#{info.inspect}"
      saveResult(analysis.scores[3] <= 0.0, 'SecurityMop2.3', @info)
    rescue Exception => e
      logInfoMsg "Error: #{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
  end
end

=begin
class SecurityMop2_3 < SecurityMop23
  include Singleton
  def initialize
    super(getRun)
  end
end
=end

################################################


def doRemoteCmd(hostname, cmd, timeout=30)
  if hostname.kind_of?(String)
    host = getRun.society.hosts[hostname]
  else
    host = hostname
  end
  cmd = "command[rexec]#{cmd}"
  logInfoMsg "doRemoteCmd: #{host.name}, #{cmd}" if $VerboseDebugging
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
  begin
    return answer[0][0]
  rescue Exception => e
    saveAssertion "doRexecCmd", "Unable to find the body tag in result (#{xml.inspect})" if $VerboseDebugging
    return ''
  end
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
