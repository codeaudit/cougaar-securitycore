require 'security/attack/attackutil'
require 'framework/security'

class CountRegistrationsBase < SecurityStressFramework
  def initialize(filename, attack, regName)
    @filename = filename
    @count = {}
    @methodNum = -1
    @attack = attack
    @regName = regName
  end

  def eventCall(event) 
    raise "This call should be overridden"
  end

  def getBaseCount()
    raise "This call should be overridden"
  end

  def preConditionalStartSociety
#    logInfoMsg "================================ Start to look for events"
    @methodNum = getRun.comms.on_cougaar_event do |event|
      eventCall(event)
    end
  end

#  def preConditionalGLSConnection
#  def postConditionalNextOPlanStage
  def postConditionalPlanningComplete
#    logInfoMsg "================================ Done looking for events"
    stop()
  end

  def postConditionalNextOPlanStage
    dumpStats("Before publishing Oplan")
  end

  def addToCount(key, value)
    array = @count[key]
    if (array == nil) 
      array = Array.new
      @count[key] = array;
    end
    # always at least replace
    array.delete(value)
    array.push(value)
  end

  def removeFromCount(key, value)
    array = @count[key]
    if (array != nil) 
      array.delete(value)
    end
  end

  def analyze
    correct = getBaseCount()
    compareHash(correct, @count)
  end

  def stop
    if @methodNum != -1
      getRun.comms.remove_on_cougaar_event @methodNum
      methodNum = -1
    else
      return nil # we've already stopped!
    end
    resultOk = dumpStatus("Final count")
    Util.saveResult(resultOk, @attack, @regName);
  end

  def dumpStats(message=nil)
    if @filename == nil
      raise "Filename is nil"
    end

    outFile = Util.mkfile(@filename,"a")
    if (message != nil)
      outFile.print(message + "\n")
    end
    outFile.print(@regName + "\n\n")
    dump(outFile, @count)
    missing = analyze()
    if missing.empty?
      outFile.print("\nNo missing registrations\n\n")
    else
      outFile.print("\nMissing registrations\n\n")
      dump(outFile, missing);
    end
    outFile.close()
    @filename = nil
    run[@regName] = nil
    missing.empty?
  end #stop

  def dump(file, hash)
    hash.each { |key,value|
      file.print("#{key}\t#{value.length}")
      if (!value.empty?)
        value.each { |agent|
          file.print("\t#{agent}")
        }
      end
      file.print("\n");
    }
  end #dump

  def compareArrays(orig, compare)
    sorted1 = orig.sort()
    sorted2 = compare.sort()
    index = 0
    missing = Array.new
    sorted1.each() do |element|
      while (index < sorted2.length &&
             sorted2[index] < element)
        index = index + 1
      end
      if (sorted2[index] != element)
        missing.push(element)
      end
    end
        missing
  end #compareArrays
  
  def compareHashKeys(orig, compare)
    missing = Hash.new
    orig.each_pair() do |key,value|
      if (!(compare.has_key? key))
        missing[key] = value
      end
    end
    missing
  end #compareHashKeys
  
  # compare a hash of arrays
  def compareHash(orig, compare)
    missing = compareHashKeys(orig, compare)
    orig.each_pair() do |key, value|
      if (!(missing.has_key? key))
        misArr = compareArrays(value, compare[key])
        if !misArr.empty?
          missing[key] = misArr
        end
      end
    end
    missing
  end #compareHash
  
end # CountRegistrationsBase

class CountMRRegistrations < CountRegistrationsBase
  def initialize
    super("#{$CIP}/workspace/test/mrreg.tbl", '2f102', "M&R Registration")
  end

  def eventCall(event)
    event.data.scan / SecurityManager\((.+)\) Analyzer\((.+)\) Operation\((.+)\) Classifications\((.+)\)/ { | match |
#      logInfoMsg "Got event: #{event.data}\n"
      agent = match[0]
      analyzer = match[1]
      operation = match[2]
      classifications = match[3].split(/, /)
      classifications.each { |c|
        if (operation == "Remove")
          removeFromCount(c, analyzer)
        else
          addToCount(c, analyzer)
        end
      }
    }
  end

  def getBaseCount
    correct = Hash.new()
    components = [
      "org.cougaar.core.security.monitoring.plugin.BootStrapEventPlugin",
      "org.cougaar.core.security.monitoring.plugin.DataProtectionSensor",
      "org.cougaar.core.security.monitoring.plugin.MessageFailureSensor",
      "org.cougaar.core.security.monitoring.plugin.CertificateRevokerPlugin",
      "org.cougaar.core.security.monitoring.plugin.LoginFailureSensor",
      "org.cougaar.core.security.monitoring.plugin.BootStrapEventPlugin"
    ]
    component_classes = [
      "org.cougaar.core.security.monitoring.SECURITY_MANAGER_EXCEPTION",
      "org.cougaar.core.security.monitoring.DATA_FAILURE",
      "org.cougaar.core.security.monitoring.MESSAGE_FAILURE",
      "org.cougaar.core.security.monitoring.MESSAGE_FAILURE",
      "org.cougaar.core.security.monitoring.LOGIN_FAILURE",
      "org.cougaar.core.security.monitoring.JAR_VERIFICATION_FAILURE"
    ]
    sensors = [
      "BootStrapEventSensor",
      "DataProtectionSensor",
      "MessageFailureSensor",
      "CertificateRevokerPlugin",
      "Login Failure Sensor",
      "BootStrapEventSensor"
    ]
    components.each_index()  { |index|
      comp = components[index]
      clz = component_classes[index]
      agents = Util.findAgentNames(comp)
      if (!agents.empty?)
        sensorlist = Array.new
        agents.each() { |agent|
          sensorlist.push(agent + "/" + sensors[index])
        }
        correct[clz] = sensorlist
      end
    }
    correct
  end
end # CountMRRegistrations


class CountCrlRegistrations < CountRegistrationsBase
  def initialize
    super("#{$CIP}/workspace/test/crlreg.tbl", '5j102', "CRL Registration")
    @baseCount = {}
  end
      
  def eventCall(event)
    event.data.scan /CrlRegistration\((.+)\) Agent\((.+)\) DN\((.+)\)/ { |match|
#      logInfoMsg "Got reg event: #{event.data}\n"
      ca = match[0]
      agent = match[1]
      dn = match[2]
      addToCount(dn, agent)
    }
    event.data.scan /CADNAddedToCertCache\((.+)\) DN\((.+)\)/ { |match|
#      logInfoMsg "Got reg req event: #{event.data}\n"
      agent = match[0]
      dn = match[1]
      array = @baseCount[dn]
      if (array == nil)
        array = [agent]
        @baseCount[dn] = array
      else
        if (!array.include? agent)
          array.push(agent)
        end
      end
    end
  end
  
  def getBaseCount
    return @baseCount
  end
end #CountCrlRegistrations

