
module Cougaar
  module Actions

    class Stressors 
      @@stresses = Hash.new;
      def Stressors.setRunState(className, methodName, runstate)
	#logInfoMsg "setRunState: #{className}.#{methodName}"
	@@stresses["#{className}.#{methodName}"] = runstate
      end

      def Stressors.getRunState(stressorClass, methodName)
	ret =  @@stresses["#{stressorClass}.#{methodName}"]
	#logInfoMsg "getRunState: #{ret}"
	return ret
      end
    end

    class StartScheduledStress < Cougaar::Action

     def initialize(run, className, methodName, delay=5.minute, interval=2.minute)
	super(run)
	begin
	  @stressor = eval("#{className}.new(run)")
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
	    rescue
	      logWarningMsg "Exception while invoking stress: #{@stressorClassName}.#{@methodName}"
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
