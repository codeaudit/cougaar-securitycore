#!/usr/bin/ruby

CIP = ENV['CIP']
$stdout.sync = true
$stderr.sync = true

# Add extra arguments to the grep function. For example, "-c" will report a count only
$extraargs = ARGV

# The directory where the log files are located
$logFileDirectory = "#{CIP}/workspace/log4jlogs"
#$logFileDirectory = "#{CIP}/../srosset/log4jlogs"

# True if performing a check for transient issues (e.g. issues that should disappear after a while)
$searchTransientIssues=true

def getStartupTime(fileName)
  aFile = File.new(fileName, "r")
  firstLine = aFile.readline
  aFile.close
  return getTime(firstLine)
end

def getTime(line)
  startuptime = nil
  line.scan(/^([0-9]*):([0-9]*):([0-9]*),([0-9]*) SHOUT(.*)/) { |x|
    time = x[0]
    #puts x[0] , x[1]
    # Time looks like this:
    # 20:51:22,234
    date = Time.now
    startuptime = Time.local(date.year, date.month, date.day, x[0], x[1], x[2])
  }

  return startuptime
end

# Search for exceptions and log4j errors, warnings, fatals
$badMessages = [
  "Exception",
  "WARN",
  "ERROR",
  "FATAL"
]

# Except for the following cases:
# This array contains pairs of (timeout, string)
# The string is a log message at warn or above, but it is actually ok in some
# circumstances.
# The timeout is a time after which we should not see the message. For example, there
# might be transient issues at startup, but after a while we should not see those issues.

$startupTime = 10 * 60

$okMessages = [
  # ############################################################### 
  # Cougaar core messages
  # ############################################################### 
  # A message is sent out and a "+" is printed on standard out.
  # standard out is logged at ERROR level.
  [nil, "STDOUT - +"],
  # A message is received out and a "-" is printed on standard out.
  # standard out is logged at ERROR level.
  [nil, "STDOUT - -"],

  # ############################################################### 
  # Security messages
  # ############################################################### 
  # An agent is unable to send a PKCS certificate signing request to the CA.
  # This may happen at startup if the CA agent is not up yet or is too busy.
  [$startupTime, "Unable to send PKCS"],
  # A Jar file was not signed properly.
  # This may happen at startup. Ruby is still in the middle of generating jar files,
  # but some nodes have already started and they are checking the signatures of all the jar files.
  [$startupTime, "xml\.jar cannot be trusted"],
  [$startupTime, "ConfigFinder - Unable to add entry"],
  [$startupTime, "Caused by: java.lang.Exception: Jar file does not have any certificate"],
  # The MTS was unable to send a message out.
  # This may happen at startup if the agent does not have a certificate, or if 
  # the remote agent does not have a certificate.
  # This applies to all four messages below.
  [$startupTime, "DestinationQueueImpl - Failure in communication"],
  [$startupTime, "MarshalException: error marshalling arguments"],
  [$startupTime, "error during JRMP connection"],
  [$startupTime, "java\.rmi\.ServerException: RemoteException occurred in server thread"],
  [$startupTime, "java\.rmi\.UnmarshalException: error unmarshalling arguments"],

  # Jena is not happy when reading files with relative paths.
  # See http://groups.yahoo.com/group/jena-dev/message/5266
  # TODO: This should really be fixed.
  [$startupTime, "{W130} Base URI is \"\""],
  # TODO: what is this? Probably Kaos
  [$startupTime, "{W101} Unqualified use of rdf:ID has been deprecated"],
  [$startupTime, "{W101} Unqualified use of rdf:resource has been deprecated"],
  # A message has been received in the clear.
  # In this specific circumstance, this is ok because RMI over SSL was used.
  [$startupTime, "Could not use protection level: SecureMethodParam: PLAIN null "],
  # Ignorable KAoS warning
  [$startupTime, "Guard is already set"],
  # A node is trying to communicate with the CA in order to submit a certificate
  # signing request (CSR). The CSR is submitted through https.
  # However, the SSL server-side certificate is not valid yet, most likely because it
  # has not been signed by a root CA yet.
  [$startupTime, "Host cert has not been signed by CA yet"],
  # A node is not able to find the certificate among its local identities, i.e., not a local agent.
  # This is not a correct warning, it warns about certificate from other nodes, which does not have
  # a local identity.
  # Complete message is:
  #   NameServerCertificateComponent - Fail to update node certificate for <node-name>
  [$startupTime, "Fail to update node certificate for"],
  # The adaptivity engine complains that no plugin has published a condition.
  # However, there is no guarantee that the M&R plugin will be started before the
  # adaptivity engine. Eventually, the plugin will be loaded and publish the condition
  [$startupTime, "No Condition named org\.cougaar\.core\.security\.monitoring\.LOGIN_FAILURE_RATE"],
 
  # ############################################################### 
  # Robustness messages
  # ############################################################### 
  # The message timeout aspect complains that a message cannot be sent in a reasonnable
  # amount of time.
  # This may happen at startup when messages stay in the queue for a long time because
  # agents do not have a certificate yet.
  [$startupTime, "MessageTimeoutAspect"],
  # ############################################################### 
  # Logistics warnings
  # ############################################################### 
  # Logistics: the scenario time is set.
  # Not sure why this is logged at WARN level
  [nil, "Starting Time set to"],
  [nil, "Expanding an already disposed task"],
  [nil, "which is before this orgs arrival time"],
=begin
  "SocketException",
  "No CertificateEntry in naming",
  "Error writing to server",
  "CommunityServiceUtil",
  "ComplainingLP - Warning",
  "RogueThreadDetector - Schedulable",
  "Host cert has not been signed",
  "PersistenceManager cert not found",
  "Unable to get Certifificate entry for DN",
  "pAssoc has null object",
  "ConnectException: Connection refused",
  "error unmarshalling arguments",
  "RemoteException occurred in server thread",
  "Error unmarshaling return",
  "BlackboardServiceProxy - QUERY DENIED",
  "No execution context available",

=end
]

def buildBadPattern()
  # Build grep pattern
  badPattern = "-nE \""
  while (x = $badMessages.shift) != nil
    badPattern << x
    if $badMessages.size > 0
      badPattern << "|"
    end
  end
  badPattern << "\""
  #puts badPattern
  return badPattern;
end

def buildOkPattern()
  okPattern = "-Ev \""
  while (x = $okMessages.shift) != nil
    okPattern << x[1]
    if $okMessages.size > 0
      okPattern << "|"
    end
  end
  okPattern << "\""
  #puts okPattern
  return okPattern
end

def searchIssues(removeOkPattern, logResultsDir)
  startupTime = 0
  badPattern = buildBadPattern()
  okPattern = buildOkPattern()
  if (logResultsDir != nil)
    Dir.mkdir(logResultsDir)
  end
  Dir.new($logFileDirectory).each do |filename|
    next if !( filename =~ /\.log/ )
    filepath = "#{$logFileDirectory}/#{filename}"
    puts "++ Checking #{filepath}"

=begin
    time = getStartupTime(filepath)
    if ((time <=> startupTime) == -1) || startupTime == 0
      startupTime = time
      #puts "Set startup time: " + startupTime.to_s
    end
=end
    if (removeOkPattern) 
      command="grep #{badPattern} #{filepath} | grep #{$extraargs} #{okPattern}"
    else
      command="grep #{badPattern} #{filepath}"
    end
    if logResultsDir != nil
      logResultsFileName = logResultsDir + "/" + filename
      command << " | tee #{logResultsFileName}"
    end
    #puts command
    system(command)
  end
  return startupTime
end

def searchTransientIssues()
  resultsDir = "#{CIP}/workspace/logAnalysis"
  startupTime = searchIssues(false, resultsDir)
  Dir.new(resultsDir).each do |filename|
    parseTimeRelatedEvents(filename, startupTime)
  end
end

def parseTimeRelatedEvents(fileName, startupTime)
  aFile = File.new(fileName, "r")
  aFile.each_line { |line|
    time = getTime(line)
    event = getEvent(line)
    okMessage.each do |x|
      if x[0] == nil 
        continue
      end
    end
  }
  aFile.close
end

searchIssues(true, nil)

