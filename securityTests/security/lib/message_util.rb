require 'security/lib/misc'
require 'thread'

MESSAGE_EVENTS = [ "Sent", "Received", "Responded", "ResponseReceived" ]

def sendRelay(source, target)
  if source.kind_of? String
    source = run.society.agents[source]
  end
  if ! target.kind_of? String
    target = target.name
  end
#  puts "sending relay message from #{source.name} to #{target}"
  url = source.uri
#  puts "the url = #{url}/message/send?xml=true&address=#{target}"
  watcher = MessageEventWatcher.new(source.name, target)
  result,url2 = Cougaar::Communications::HTTP.get("#{url}/message/send?xml=true&address=#{target}")
  raise "Error sending message from #{source.name} to #{target}" unless result
  #        puts "sent relay message: #{result}"
  uid = nil
#  puts "result type = #{result.class}"
  result.scan(%r"<uid>([^<]+)</uid>") { |match|
    uid = match[0]
  }
  if uid == nil
    watcher.stop
    puts url
    puts url2
    puts result
    raise "Could not extract UID from response when sending " +
      "message from #{source.name} to #{target}"
  end
  watcher.setUID(uid)
  watcher
end # sendRelay

def testMessageFailure(source, target,
                       attackNum, attackName,
                       responsesExpected,
                       maxWait = 2.minutes)
  expected = {}
  MESSAGE_EVENTS.each_index { |index|
    expected[MESSAGE_EVENTS[index]] = responsesExpected[index]
  }

  #	puts "started idmefWatcher"        
  watcher = sendRelay(source, target);
  Thread.fork {
#    puts "\n================== sleeping...."
#    begin
      sleep(maxWait)
#    rescue
#      puts "\n================== caught a problem!", $!
#    end
#    puts "\n================== done sleeping"
    watcher.stop
#    puts ("\n================== stopped...")
    saveResult(watcher.getHash() == expected,
               attackNum, attackName + ". " +
               source + " => " + target + " - " + 
               watcher.getArray().join("\t"))
#    puts("\n================== saved result")
  }
end # testMessageFailure

def testMessageIdmef(source, target, 
                     idmefNum, idmefName,
                     responsesExpected, stoppingAgent,
                     maxWait = 3.minutes)
  expected = {}
  MESSAGE_EVENTS.each_index { |index|
    expected[MESSAGE_EVENTS[index]] = responsesExpected[index]
  }
  idmefSrc = source
  idmefTgt = target
  if (expected["Received"])
    idmefSrc = target
    idmefTgt = source
    maxWait = 6.minutes
  end
  shouldStop = true
  if (stoppingAgent == nil)
    shouldStop = false
    stoppingAgent = "[-0-9a-zA-Z_]+"
  end

  #	puts "about to create idmef watcher"
  idmefWatcher = 
    IdmefWatcher.new(idmefNum, idmefName, shouldStop,
                     "IDMEF\\(#{stoppingAgent}\\) Classification\\(org.cougaar.core.security.monitoring.MESSAGE_FAILURE\\) Source\\([^)]+\\) Target\\([^)]+\\) AdditionalData\\(([^,]+,)*((SOURCE_AGENT:#{idmefSrc})|(TARGET_AGENT:#{idmefTgt})),([^,]+,)*((SOURCE_AGENT:#{idmefSrc})|(TARGET_AGENT:#{idmefTgt}))(,[^,)]+)*\\)")
  idmefWatcher.start

  Thread.fork {
    #          puts "sleeping...."
    sleep(maxWait)
    #          puts "done sleeping"
    idmefWatcher.stop

  }
end # testMessageIdmef


def testMessageSuccess(source, target, attackNum, attackName, 
                       maxWait = 2.minutes)
  testMessageFailure(source, target,
                     attackNum, attackName, 
                     [ true, true, true, true ],
                     maxWait)
end # testMessageSuccess

class MessageEventWatcher
  def initialize(source, target)
    @hash = { }
    MESSAGE_EVENTS.each { |event|
      @hash[event] = false
    }
    @uid = nil
    @array = []
    @events = []
    @source = source
    @target = target
    @mutex = Mutex.new()

    @listener = run.comms.on_cougaar_event { |event|
      @mutex.synchronize do
        if (@uid == nil)
          if (event.data =~ /MessageTransport\(.+\) UID\(.+\) Source\(#{@source}\) Target\(#{@target}\)/)
            @events.unshift(event)
          end
        else
          event.data.scan(/MessageTransport\((.*)\) UID\(#{@uid}\) Source\(#{@source}\) Target\(#{@target}\)/) { |match|
            @array << match[0]
            @hash[match[0]] = true
            if (match[0] == "ResponseReceived")
              stop
            end
          }
        end
      end
    }
  end

  def parseOldEvents()
    @events.each { |event|
      event.data.scan(/MessageTransport\((.*)\) UID\(#{@uid}\) Source\(#{@source}\) Target\(#{@target}\)/) { |match|
        @array.unshift(match[0])
        @hash[match[0]] = true
        if (match[0] == "ResponseReceived")
          stop
        end
      }
    }
    @events.clear
  end

  def setUID(uid)
    @mutex.synchronize do
      if (@uid == nil)
        @uid = uid
        parseOldEvents
      end
    end
  end
  
  def stop
    if (@listener != nil)
      run.comms.remove_on_cougaar_event(@listener)
      @listener = nil
    end
  end

  def getHash
    return @hash
  end

  def getArray
    return @array
  end
end # MessageEventWatcher

class IdmefWatcher 
  def initialize(attackNum, attackName, expected, idmefText)
    @attackNum = attackNum
    @attackName = attackName
    @expected = expected
    @idmefText = idmefText
    @idmefFound = false
    @listener = -1
  end

  def start
    logInfoMsg "Starting a listener with pattern --> #{@idmefText}" if $VerboseDebugging
    @listener = run.comms.on_cougaar_event do |event|
      if event.data =~ /#{@idmefText}/
        # it gave an event
        @idmefFound = true
        #logInfoMsg " found pattern #{@idmefText}"
        stop
      end
      #if event.component == 'IdmefEventPublisherPlugin'
      #  logInfoMsg " Event data is #{event.data}"
      #  logInfoMsg " pattern to match is #{@idmefText}"
      #end
    end
  end # start
  
  def stop
    if @listener != -1
      run.comms.remove_on_cougaar_event(@listener)
      @listener = -1
      saveResult(@idmefFound == @expected, @attackNum,
		 "#{@attackName} - Idmef event found: #{@idmefFound} - Idmef event expected: #{@expected} - Expected text: #{@idmefText}")
    end
  end
end #IdmefWatcher

