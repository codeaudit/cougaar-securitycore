
# $configuredSecurityTests contains the list of tests that should be
# executed during a given experiment.
if !defined? $configuredSecurityTests
  $configuredSecurityTests = []
end

module Cougaar
  module Actions

    $Dbg_action = false

    class MyExperiment
      attr_accessor :run
      def initialize(run)
	@run = run
      end
    end

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
          begin
	    ret = eval("#{stressorClass}.new(run)")
          rescue => ex
            if ex.message =~ /private method `new' called/
	      ret = eval("#{stressorClass}.instance(run)")
            else
              raise ex
	    end
          end
	  begin
	    # Get the names of the stresses.
            $configuredSecurityTests.concat( ret.getStressIds() )
          rescue
            logWarningMsg "The stressor class should implement a getStressIds() method"
          end
	  ret.myexperiment = MyExperiment.new(run)
	  setMyRun(run)
	  #puts "Run.name: #{run.name} Experiment: #{run.experiment.name}"
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
	  logInfoMsg "Unable to start stress: #{@stressorClassName} - " + ex
          saveResult(false, "Stress: #{@stressorClassName}.#{@methodName}",
             "#{ex}\n#{ex.backtrace.join("\n")}", "testClass")
	  return
	end
      end

      def perform()
	logInfoMsg "Starting stress: #{@stressorclassName}.#{@methodName}" if $Dbg_action
	if @stressor == nil
	  return
	end
	logInfoMsg "Invoking stress: #{@stressorClassName}.#{@methodName}"
	t1 = Time.now
	begin
	  @aMethod.call()
	rescue => ex
	  logInfoMsg "Exception while invoking stress: #{@stressorClassName}.#{@methodName}"
          saveResult(false, "Stress: #{@stressorClassName}.#{@methodName}",
               "#{ex}\n#{ex.backtrace.join("\n")}", "testClass")
	end
	t2 = Time.now
	logInfoMsg "Done invoking stress: #{@stressorClassName}.#{@methodName} in #{t2 - t1} seconds"
      end
    end

    class StartScheduledStress < Cougaar::Action

     def initialize(run, className, methodName, delay=0.minute, interval=2.minute)
	super(run)
	begin
	  @stressor = Stressors.getStressInstance(className, run)
	  @aMethod = @stressor.method(methodName)
	rescue => ex
	  logInfoMsg "Unable to start stress: #{className} - " + ex
          saveResult(false, "Stress: #{className}.#{methodName}",
             "#{ex}\n#{ex.backtrace.join("\n")}", "testClass")
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
	    logInfoMsg "Invoking scheduled stress: #{@stressorClassName}.#{@methodName}"
	    begin
	      @aMethod.call()
	    rescue => ex
	      logInfoMsg "Exception while invoking stress: #{@stressorClassName}.#{@methodName}"
              saveResult(false, "Stress: #{@stressorClassName}.#{@methodName}", 
                  "#{ex}\n#{ex.backtrace.join("\n")}", "testClass")
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
	  logInfoMsg "Stress: #{@stressorClassName}.#{@methodName} is not set"
	  return
	end
	Stressors.setRunState(@stressorClassName, @methodName, false)
      end
    end

  end
end
