#
#  <copyright>
#  Copyright 2003 SRI International
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#

#require 'lib/experimentFramework'

$CIP = ENV['COUGAAR_INSTALL_PATH']
#$User = ''
begin
  # does this work on Windows machines?
  $User = `whoami`
rescue
  $User = 'asmt'
end

#$AutomationDir

# Define the as_string method  ****************************
class Object
  def as_string
    self.to_s
  end
end
class NilClass
  def as_string
      'ni'
  end
end
class String
  def as_string
    return "\""+self+"\""
  end
end
class Hash
  def as_string
    result = []
    self.each {|key,value| result << key.as_string+" => "+value.as_string}
    return "{ "+result.join(", ")+" }"
  end
end
module Enumerable
  def as_string
    return "["+(self.collect {|i| i.as_string}).join(", ")+"]"
  end
end

#-----------

class String
  def downcaseFirstLetter
    return self.downcase if self.size<=1
    self[0..0].downcase+self[1..-1]
  end
end

#------------

def addToConfigPath(agent, path)
  newpath = "#{$CIP}/configs/#{path};"
  test_cougaar_config_path = agent.node.get_parameter("-Dorg.cougaar.config.path")
  # Add the specified path unless it is already present
  if test_cougaar_config_path.scan(newpath) != []
    test_cougaar_config_path = "#{newpath}"+test_cougaar_config_path
    logInfoMsg "new #{agent.name} config path = #{test_cougaar_config_path}"
    agent.node.override_parameter("-Dorg.cougaar.config.path",  test_cougaar_config_path)
  end
end

def copyConfigDirTo(agent, dirname, force=false)
  logInfoMsg "Copying config dir to #{dirname}"
  @copiedConfigDirs = {} unless defined? @copiedConfigDirs
  key = [agent, dirname]
  if force or @copiedConfigDirs.has_key? key
    removeConfigDir agent, dirname
    runCommandAs agent, $User, "cp -rp #{$CIP}/configs/security/configs/#{dirname}"
    @copiedConfigDirs[key] = true
  end
end

def removeConfigDir(agent, dirname, force=false)
  @removedConfigDirs = {} unless defined? @removedConfigDirs
  key = [agent, dirname]
  if force or not @removedConfigDirs.has_key? key
    runCommandAs agent, $User, "rm -rf #{$CIP}/configs/#{dirname}"
    @removedConfigDirs[key] = true
  end
end

def copyConfigFile(agent, fromfile, dirname, toname)
  runCommandAs agent, $User, "cp -f #{$AutomationDir}/configs/#{fromfile} #{$CIP}/configs/#{dirname}/#{tofile}"
end

def backupConfigFile(agent, file)
  @backedUpConfigFiles = {} unless @backedUpConfigFiles
  filename = "#{$CIP}/#{file}"
  origfile = filename+'.orig'
  key = [agent, file]
  unless @backedUpConfigFiles[file]
    runCommandAs agent, $User, "cp #{$CIP}/#{file} #{$CIP}/#{file}.orig" unless File.exist?(origfile)
    @backedUpConfigFiles[key] = true
  end
end

def restoreBackupConfigFiles
  @backedUpConfigFiles.keys.each do |agentAndFilename|
    agent = agentAndFilename[0]
    file = agentAndFilename[1]
    runCommandAs agent, $User, "mv -f #{$CIP}/#{file}.orig #{$CIP}/#{file}"
  end
end

def removeMetaInf(agent, file)
  runCommandAs agent, $User, "zip -d #{$CIP}/#{file} META-INF/\\*\""
end

def getAEViewerOutput
  getAEViewerOutputFor 'SocietySecurityMnRManagerAgent'
end

def getAEViewerOutputFor(agentName)
  #Capture the output of Adaptivity Viewer Servlet
  logInfoMsg "Capture the output of Adaptivity Viewer Servlet for #{agent}"
  agent = getAgent agentName
  if agent
    url = "#{agent.uri}/$#{agentName}/aeviewer"
    puts "Logging output of #{url}"
    #resp = Util.do_http_request(url)[0]
    resp = getHtml(url)
    logInfoMsg "\nStart Output of aeviewer Servlet."
    if resp
      logInfoMsg "#{resp.body}"
    else
      logInfoMsg "Error Status: #{resp.code}"
    end
    logInfoMsg "End Output of aeviewer Servlet.\n"
    resp
  end
end

def runCommandAs(agent, user, command)
  #Cougaar::myexperiment.runCommandAs(agent, user, command)
  getRun.myexperiment.runCommandAs(agent, user, command)
end






module Enumerable
  # ruby 1.8 is supposed to include #inject.
  # use this until we make the switch
  def injectIt(startValue)
    each {|value| startValue = yield startValue, value}
    return startValue
  end
end


########################################

# Logging methods

def logInfoMsg(msg='')
  # Cougaar.logger.info  "[#{Time.now}]     #{msg}"
  if defined?(Cougaar::Run) and getRun
    if msg and msg!=''
      getRun.info_message msg
    else
      getRun.info_message ''
    end
  else
    if msg and msg!=''
      puts "[#{Time.now}]     #{msg}"
    else
      puts
    end
  end
end

def logWarningMsg(msg='')
  logInfoMsg "*********** WARNING ************"
  logInfoMsg msg
  logInfoMsg "********************************"
end

def logErrorMsg(msg='')
  logInfoMsg "************ ERROR *************"
  logInfoMsg msg
  logInfoMsg "********************************"
end

def logExceptionMsg(msg='')
  errTrace = $!
  if errTrace
    backtrace = $!.backtrace.join("\n")
    logErrorMsg msg+"\nCurrently in state ???\n"+errTrace.to_s+"\n"+backtrace.to_s
  else
    logErrorMsg msg+"\nCurrently in state ???"
  end
end

# Call this when you can't recover from an error
def criticalError(msg='Critical error')
  logExceptionMsg msg
  do_action 'StopSociety' if getRun
  exit 1
end



module Cougaar
  module Actions
    class Irb < Cougaar::Action
      def initialize(run, prompt='ruby')
        super(run)
        @prompt = prompt
      end
      def perform
        @run.doIrb(@prompt)
      end
    end
  end
end



def getAgentsWithPlugin(run, classnameMatch)
  agents = []
  run.society.each_agent(true) do |agent|
    agent.each_component do |plugin|
      if classnameMatch =~ plugin.classname
        agents << agent.name
      end
    end
  end
  agents
end


def getAgent(agent)
  getRun.society.agents[agent]
end


module Cougaar
  module Model
    class Society
      def entity(name)
        entity = agents[name]
        entity = nodes[name] unless entity
        entity = hosts[name] unless entity
        return entity
      end
    end
  end
  module Actions
    class Exit < Cougaar::Action
      def perform
        exit
      end
    end
    class Puts < Cougaar::Action
      def initialize(run, str)
        super(run)
        @str = str
      end
      def perform
        puts instance_eval(@str).inspect
      end
    end
  end
end


def timeBlock(actionDescription="run code")
  # Note: variables which are first set in the block cannot be seen outside the scope of the block.
  #    Preset variables are within the scope of this block.
  startTime = Time.now
  yield
  endTime = Time.now
  logInfoMsg "it took #{endTime-startTime} seconds to #{actionDescription}"
end


#--------------------------------
#    facet methods
#--------------------------------

def getHostFacets(run)
  #   unless facets
  if true
    facets = {}
    run.society.each_host do |host|
      host.each_facet do |facet|
        facets[facet] = [] unless facets.has_key? facet
        facets[facet] << host
      end
    end
    @hostFacets = facets
  end
  @hostFacets
end
#f=getFacets run

def getNodesWithFacet(run, key, value)
  run.society.hosts.each_facet(key) do |facet|
    puts facet
  end
end
#getNodesWithFacet('service', 'acme')

module Cougaar
  module Model
    module Multifaceted
      def facet_keys
        keys = []
        each_facet {|f| f.themap.each_key {|k| keys << k}}
        keys.uniq
      end
      class Facet
        def themap
          @map
        end
      end
    end
  end
end
#run.society.hosts['sv100'].themap

class Dir
  def self.mkdirs(dir)
    head, tail = File.split(dir)
    if (head != dir)
      mkdirs(head)
    end

    begin
      stat = File.stat(dir)
    rescue Exception
      Dir.mkdir(dir)
    end
  end # mkdirs
end # Dir

class File
  def self.rm_all(entry)
    stat = nil
    begin
      stat = File.stat(entry)
    rescue Exception
      return nil
    end
    if stat.directory?
      Dir.foreach(entry) { |file|
        if (file != "." && file != "..")
          rm_all(File.join(entry,file))
        end
      }
      Dir.unlink(entry)
    else
      File.unlink(entry)
    end
  end

  def self.cp(fromFile, toFile)
    begin
      if File.stat(toFile).directory?
        to = File.join(toFile, File.basename(fromFile))
      end
    rescue Exception
      # don't worry about it if the file doesn't exist
    end
    File.open(fromFile, "r") { |from|
      File.open(toFile, "w") { |to|
        while (!from.eof?)
          buf = from.read(1000)
          if (buf != nil)
            to.write(buf)
          end
        end
      }
    }
  end # cp
end # File

def getTestResultFile()
  filename = "#{$CIP}/workspace/test/attack_results.log"
  Dir.mkdirs(File.dirname(filename))
  File.new(filename,"a")
end

$TestResults = []
def saveResult(pass, testnum, testname)
  success = "SUCCESS"
  if !pass
    success = "FAILURE"
  end
  file = getTestResultFile()
  file.print(success + "\t" + testnum + "\t" + testname + "\n");
  file.close();
  summary([success, testnum, testname].join("\t"))
  $TestResults << [ pass, testnum, testname ]
end # saveResult

def getClasspath
  classpath = []
  Dir.foreach("#{$CIP}/lib") { |file|
    if (file =~ /\.jar$/)
      classpath << File.join($CIP, "lib", file)
    end
  }
  Dir.foreach("#{$CIP}/sys") { |file|
    if (file =~ /\.jar$/)
      classpath << File.join($CIP, "sys", file)
    end
  }
  classpath
end
