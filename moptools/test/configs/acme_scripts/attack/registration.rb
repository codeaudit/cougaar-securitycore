require 'security/attack/attackutil'
require 'framework/security'

class CountRegistrationsBase < SecurityStressFramework
  def initialize(filename, regName)
    @filename = filename
    @count = {}
    @methodNum = -1
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
    success = "FAILED"
    if (dumpStats("Final count")) 
      success = "SUCCESS"
    end
    file = Util.getTestResultFile
    file.print(success + "\t" + @regName + "\n")
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
    super("#{$CIP}/workspace/test/mrreg.tbl", "M&R Registration")
  end

  def eventCall(event)
    if event.data =~ / SecurityManager\((.+)\) Analyzer\((.+)\) Operation\((.+)\) Classifications\((.+)\)/
#      logInfoMsg "Got event: #{event.data}\n"
      agent = $1
      analyzer = $2
      operation = $3
      classifications = $4.split(/, /)
      classifications.each { |c|
        if (operation == "Remove")
          removeFromCount(c, analyzer)
        else
          addToCount(c, analyzer)
        end
      }
    end
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
      agents = Util.findAgentNames(run.society, comp)
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
    super("#{$CIP}/workspace/test/crlreg.tbl", "CRL Registration")
    @baseCount = {}
  end
      
  def eventCall(event)
    if event.data =~ /CrlRegistration\((.+)\) Agent\((.+)\) DN\((.+)\)/
#      logInfoMsg "Got reg event: #{event.data}\n"
      ca = $1
      agent = $2
      dn = $3
      addToCount(dn, agent)
    elsif event.data =~ /CADNAddedToCertCache\((.+)\) DN\((.+)\)/
#      logInfoMsg "Got reg req event: #{event.data}\n"
      agent = $1
      dn = $2
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

class Security2f102Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-2f102'
    @stresses = [ CountMRRegistrations ]
  end
end

class Security5j102Experiment < SecurityExperimentFramework
  def initialize
    super
    @name = 'CSI-Security-5j102'
    @stresses = [ CountCRLRegistrations ]
  end
end
