#!/usr/bin/ruby

######################################################################
# Data Section
#


# Search for exceptions and log4j errors, warnings, fatals
$badMessages = [
  /Exception/,
  /WARN/,
  /ERROR/,
  /FATAL/
]


$startupDelay = 10 * 60

# Except for the following cases: This array contains pairs of
# (timeout, string) The string is a log message at warn or above, but
# it is actually ok in some circumstances.  The timeout is a time
# after which we should not see the message. For example, there might
# be transient issues at startup, but after a while we should not see
# those issues.
$okMessages= [
  [nil, /STDOUT - \+/],
  [nil, /STDOUT - -/],
  [nil, /STDOUT - $/],
  [nil, /STDOUT - R$/],
  [nil, /WARN  -.*STDOUT -.*SHOUT \[DOTS\]/],
  [nil, /STDOUT - \./],
  [nil, /STDOUT - P$/],
  [nil, /TWRIGHT upInc/],
  # ############################################################### 
  # Security messages
  # ############################################################### 

  [$startupDelay, /STDOUT - Creating Msg proxy. Requestor/],

  # An agent is unable to send a PKCS certificate signing request to the CA.
  # This may happen at startup if the CA agent is not up yet or is too busy.
  [$startupDelay, /Unable to send PKCS/],

  [nil, /java.io.IOException: Sender should be signing, Probable cause = new ssl credentials or policy mismatch/],

  # A Jar file was not signed properly.
  # This may happen at startup. Ruby is still in the middle of generating jar files,
  # but some nodes have already started and they are checking the signatures of all the jar files.
  [$startupDelay, /xml\.jar cannot be trusted/],
  [$startupDelay, /ConfigFinder - Unable to add entry/],
  [$startupDelay, /Caused by: java.lang.Exception: Jar file does not have any certificate/],
  #
  # early certificate exceptions
  #
  [$startupDelay, /WARN  - TrustManager - Failed to verify certificate: /],
  [$startupDelay, /org.cougaar.core.security.crypto.CertificateChainException: Failed to establish chain from reply - TRUST_SELF_SIGNED/],

  # The MTS was unable to send a message out.
  # This may happen at startup if the agent does not have a certificate, or if 
  # the remote agent does not have a certificate.
  # This applies to all four messages below.
  [$startupDelay, /DestinationQueueImpl - Failure in communication/],
  [$startupDelay, /MarshalException: error marshalling arguments/],
  [$startupDelay, /error during JRMP connection/],
  [$startupDelay, /java\.rmi\.ServerException: RemoteException occurred in server thread/],
  [$startupDelay, /java\.rmi\.UnmarshalException: error unmarshalling arguments/],

  # Jena is not happy when reading files with relative paths.
  # See http://groups.yahoo.com/group/jena-dev/message/5266
  # TODO: This should really be fixed.
  [$startupDelay, /\{W130\} Base URI is \"\"/],
  # TODO: what is this? Probably Kaos
  [$startupDelay, /\{W101\} Unqualified use of rdf:ID has been deprecated/],
  [$startupDelay, /\{W101\} Unqualified use of rdf:resource has been deprecated/],
  # A message has been received in the clear.
  # In this specific circumstance, this is ok because RMI over SSL was used.
  [$startupDelay, /Could not use protection level: SecureMethodParam: PLAIN null /],
  # Ignorable KAoS warning
  [nil, /Guard is already set/],
  # A node is trying to communicate with the CA in order to submit a certificate
  # signing request (CSR). The CSR is submitted through https.
  # However, the SSL server-side certificate is not valid yet, most likely because it
  # has not been signed by a root CA yet.
  [$startupDelay, /Host cert has not been signed by CA yet/],
  # A node is not able to find the certificate among its local identities, i.e., not a local agent.
  # This is not a correct warning, it warns about certificate from other nodes, which does not have
  # a local identity.
  # Complete message is:
  #   NameServerCertificateComponent - Fail to update node certificate for <node-name>
  [$startupDelay, /Fail to update node certificate for/],
  # The adaptivity engine complains that no plugin has published a condition.
  # However, there is no guarantee that the M&R plugin will be started before the
  # adaptivity engine. Eventually, the plugin will be loaded and publish the condition
  [$startupDelay, /No Condition named/],
  #
  # Caused by ProtectionLevel message that bypasses the MTS
  #
  [$startupDelay, /MTImpl - No incarnation number in message/],
  [$startupDelay, /MTImpl - message type/],
  [$startupDelay, /MTImpl - message object/],
 
  # ############################################################### 
  # Robustness messages
  # ############################################################### 
  # The message timeout aspect complains that a message cannot be sent in a reasonnable
  # amount of time.
  # This may happen at startup when messages stay in the queue for a long time because
  # agents do not have a certificate yet.
  [$startupDelay, /MessageTimeoutAspect/],
  # ############################################################### 
  # Logistics warnings
  # ############################################################### 
  # Logistics: the scenario time is set.
  # Not sure why this is logged at WARN level
  [nil, /Starting Time set to/],
  [nil, /Expanding an already disposed task/],
  [nil, /which is before this orgs arrival time/],
  [nil, /Avoiding "UID mismatch" bug 3774/],

  # This is part of another exception - maybe i misnamed this class
  [nil, /^\s*at org.cougaar.core.security.crypto.RemotePolicyExceptionAspect/],
  [nil, /ALCommBasedRegistrationPlugin - .*: updateRegisterTaskDisposition.. leaving confidence at 1.0 after rehydration even though reregistration is not complete./],
  ############################################################
  # Possible issues
  ###########################################################
  [nil, /WARN  - Inventor.*Bug \#13532 - Execute cycle terminated/],
  [nil, /WARN.*LogisticsInventoryBG .*not adding projection to deleted buckets/],
  [nil, /WARN.*LogisticsInventoryBG.*not adding demand for old projection/],
  [nil, /WARN  - InventoryPlugin.* Trying to rescind and reallocate unprovided supply refill tasks/],
  [nil, /WARN  - InventoryPlugin.*GetSplitTimes\.\.\. task is:/],
  [nil, /WARN  - InventoryPlugin.*TRYING TO ALLOCATE PROJECTION REFILL TASKS/],
  [nil, /WARN.*VishnuPlugin.*no expansion of mp task.*must be in the middle of rescinds/],
  [$startupDelay, /TrafficMatrixResponsePlugin - .*: Wake interval reset from from specified -1 to minimum accepted value:/],
  ###########################################################
  # Temporarily ignoring the following for now...
  ###########################################################
  [nil, /No incarnation number in message/],
  [nil, /OldIncarnationAspect/],
]

$repeatingErrors = [
   /DeliveryVerificationAspect/,
   /MessageTimeoutAspect/,
   /Failure in communication/,
   /Connection reset/,
   /Connection refused/,
   /Unable to get Certifificate entry for DN/,
   /ALDynamicSDClientPlugin.*Unable to generate .* for .*/,
   /KeyRing.*Missing certificate for.*adding it to request/,
   /RogueThreadScheduler/,
   /isSelfPropelled - found task /,
   /.*VishnuPlugin - .*VishnuPlugin - unexpected : there already is a task .* in table with key .* it was .*/,
   /WARN  - LineagePlugin - .* has Lineage: UID=.*, type=.*, list=.*, schedule=/,
]

#
# Errors that are so bad that we don't want to miss them
#
$fatalErrors = [
   /SuicideService/
]



######################################################################
# Code Section
#

$repeatCount = 3

#
# a class to facilitate lazy evaluation of Time.local
#  Might be even better if I didn't use Time.local?
#
class MyTime
  @@timeRegexp = /^([0-9]*)-([0-9]*)-([0-9]*) ([0-9]*):([0-9]*):([0-9]*),([0-9]*)[^0-9]/

  def initialize(message)
    if @@timeRegexp.match(message) == nil then
      raise "Could not set time"
    end
    @message = message
    @time    = nil
  end

  def getTime()
    if @time then
      return @time
    else 
      @message.scan(@@timeRegexp) do |x|
        #puts x[0] , x[1]
        # Time looks like this:
        # 2004-04-12 20:51:22,234
        @time = Time.local(x[0], x[1], x[2], x[3], x[4], x[5])
        return @time
      end
    end
    return nil
  end

  def MyTime.goodLogMsg(message)
    return (@@timeRegexp.match(message) != nil)
  end
end


def checkLogs(path)
  fatals = []
  Dir.glob(File.join(path, "*.log")).each do |file|
    repeats = copyRepeats
    File.open(file) do |fd|
      currentTime = MyTime.new(fd.gets())
      startTime = currentTime.getTime()
      nobadlogs = true
      fd.each_line do |logmsg|
        if badMessage(logmsg) then
          if MyTime.goodLogMsg(logmsg) then
            currentTime = MyTime.new(logmsg)
          end
          if $endTime != nil && ((currentTime.getTime <=> $endTime) > 0) then
             break
          end
          if !actuallyOk(startTime, currentTime, logmsg) then
            if nobadlogs then
              nobadlogs = false
              banner(startTime, file)
            end
            if isFatal(logmsg) then
              fatals.push(logmsg)
            end
            if allowRepeats(logmsg, repeats) then
              puts "\t#{logmsg}"
            end
          end
        end
      end
    end
  end
  if !fatals.empty? then
    puts "==================================================="
    puts "***************************************************"
    puts "FATAL FATAL FATAL FATAL FATAL FATAL FATAL FATAL FATAL FATAL"
    puts "The following serious errors were found"
    fatals.each do |msg|
      puts "\t#{msg}"
    end
  end
end

def banner(startTime, file)
  puts("------------------------------------------------------")
  puts("Log File: #{file}")
  puts("Start Time: #{startTime}")
  if ($endTime) then
    puts("End Time: #{$endTime}")
  end
  puts("------------------------------------------------------")
end

def badMessage(logmsg)
  $badMessages.each do |regexp|
    if regexp.match(logmsg) then
      return true
    end
  end
  return false
end

def actuallyOk(startTime, currentTime, logmsg)
  $okMessages.each do |msgspec|
    time   = msgspec[0]
    regexp = msgspec[1]
    if regexp.match(logmsg) then
      if time == nil || ((currentTime.getTime <=> startTime + time) < 0) then
        return true
      end
    end
  end
  return false
end

def isFatal(logmsg)
  $fatalErrors.each do |regexp|
    if regexp.match(logmsg) then
      return true
    end
  end
  return false
end

def copyRepeats()
  repeats = [] 
  $repeatingErrors.each do |repeatSpec|
    repeats.push([repeatSpec, $repeatCount])
  end
  repeats
end

def allowRepeats(logmsg, repeats)
  repeats.each do |repeatSpec|
    regexp     = repeatSpec[0]
    remaining  = repeatSpec[1]
    if regexp.match(logmsg) then
      repeatSpec[1] -= 1
      if remaining > 0 then
        return true
      elsif remaining == 0 then
        puts("\t*****")
        puts("\tMore instances of pattern #{regexp}")
        puts("\t*****")
        return false
      else 
        return false
      end
    end
  end
end


def processArgs()
 cip = ENV['CIP']
 $logdir  = File.join(cip, "workspace", "log4jlogs")
 $endTime = nil
 ARGV.each do |line|
   puts  "Argument = #{line}"
   m = nil
   if m=/^--logdir=(.*)$/.match(line) then
     $logdir = m[1]
   elsif m=/^--lastlog=(.*)$/.match(line) then
     $endTime = MyTime.new("#{m[1]}x").getTime
      puts "Logs end at #{$endTime}"
   elsif /^--help$/.match(line) then
     usage
   else 
     usage
   end
 end
 puts "logging dir = #{$logdir}"
end


def usage()
  puts "Use --logdir=... to set the directory of the log files"
  puts "Use --lastlog= to set the time to stop processing messages"
  puts "\tEnter time in format 2004-09-23 06:24:19,448"
  puts "\tUse double quotes to put the entire thing as one argument"
  puts "--help will generate this message"
  exit
end

def debug(s)
  if $debug then 
    puts(s)
  end
end


#####################################################################
#
# Execution Section
#

processArgs
checkLogs($logdir)
