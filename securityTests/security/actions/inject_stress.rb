
module Cougaar
  module Actions

    $Dbg_action = false

    class Stressors 
      # A hash map indexed by #{className}
      # Value is the instance of the stress class

      @@stressMap = Hash.new
      # A hash map indexed by #{className}.#{methodName}
      # Value is boolean: true means scheduled stress should go on.
      #                   false means scheduled stress should be stopped.
      @@stressesState = Hash.new

      def Stressors.setRunState(className, methodName, runstate)
	logInfoMsg "setRunState: #{className}.#{methodName}" if $Dbg_action
	@@stressesState["#{className}.#{methodName}"] = runstate
      end

      def Stressors.getRunState(stressorClass, methodName)
	ret =  @@stressesState["#{stressorClass}.#{methodName}"]
	logInfoMsg "getRunState: #{ret}"  if $Dbg_action
	return ret
      end

      def Stressors.getStressInstance(stressorClass, run) 
	ret =  @@stressMap[stressorClass]
	if (ret == nil) 
	  ret = eval("#{stressorClass}.new(run)")
	  @@stressMap[stressorClass] = ret
	end
	return ret
      end
    end

   class InjectStress < Cougaar::Action

     def initialize(run, className, methodName)
	super(run)
	@stressorClassName = className
	@methodName = methodName
	begin
	  #logInfoMsg "Starting stress1: #{@stressorClassName}.#{@methodName}"
	  @stressor = Stressors.getStressInstance(className, run)
	  @aMethod = @stressor.method(methodName)
	rescue => ex
	  logWarningMsg "Unable to start stress: #{@stressorClassName}" + ex
          saveResult(false, "Stress: #{@stressorClassName}.#{@methodName}", ex)
	  return
	end
      end

      def perform()
	logInfoMsg "Starting stress: #{@stressorclassName}.#{@methodName}" if $Dbg_action
	if @stressor == nil
	  return
	end
	logInfoMsg "Invoking stress: #{@stressorClassName}.#{@methodName}"
	begin
	  @aMethod.call()
	rescue => ex
	  logWarningMsg "Exception while invoking stress: #{@stressorClassName}.#{@methodName}"
          saveResult(false, "Stress: #{@stressorClassName}.#{@methodName}",
               "#{ex}\n#{ex.backtrace.join("\n")}")
	end
	logInfoMsg "Done invoking stress: #{@stressorClassName}.#{@methodName}" if $Dbg_action
      end
    end

    class StartScheduledStress < Cougaar::Action

     def initialize(run, className, methodName, delay=0.minute, interval=2.minute)
	super(run)
	begin
	  @stressor = Stressors.getStressInstance(className, run)
	  @aMethod = @stressor.method(methodName)
	rescue => ex
	  logWarningMsg "Unable to start stress: #{className}" + ex
	  return
	end

	@delay = delay
	@interval = interval
	@stressorClassName = className
	@methodName = methodName
      end

      def perform()
	#logInfoMsg "Starting stress: #{@stressorClassName}.#{@methodName}"
	if @stressor == nil
	  return
	end
        Thread.fork {
	  #logInfoMsg "Delay Invoke stress: #{@stressorClassName}.#{@methodName} #{@delay}"
	  sleep @delay
	  Stressors.setRunState(@stressorClassName, @methodName, "true")
	  id = 0
	  while (Stressors.getRunState(@stressorClassName, @methodName)) 
	    logInfoMsg "Invoking stress: #{@stressorClassName}.#{@methodName}"
	    begin
	      @aMethod.call()
	    rescue => ex
	      logWarningMsg "Exception while invoking stress: #{@stressorClassName}.#{@methodName}"
              saveResult(false, "Stress: #{@stressorClassName}.#{@methodName}", 
                  "#{ex}\n#{ex.backtrace.join("\n")}")
	    end
	    id += 1
	    sleep @interval
          end
	  logInfoMsg "No longer invoking stress: #{@stressorClassName}.#{@methodName}"
        }
      end
    end

    class StopScheduledStress < Cougaar::Action
      def initialize(run, className, methodName)
	super(run)
	@stressorClassName = className
	@methodName = methodName
      end
      def perform()
	#logInfoMsg "Stopping stress: #{@stressorClassName}.#{@methodName}"
	val = Stressors.getRunState(@stressorClassName, @methodName)
	if (val == nil || !val)
	  logWarningMsg "Stress: #{@stressorClassName}.#{@methodName} is not set"
	  return
	end
	Stressors.setRunState(@stressorClassName, @methodName, false)
      end
    end

  end
end
