SecurityMopDir = "#{ENV['CIP']}/workspace/security/mops"
DbFilename = "#{SecurityMopDir}/mops"


module Cougaar
  module Actions

    class StoreMopsInRunHashTable < Cougaar::Action
      # this is used only trying to use CSI's InjectStresses at the
      # same time as running the assessment mops.
      def initialize(run)
        super(run)
      end

      def perform
        # the first slot is a placehold so that mop 2.1 is at index 1.
        begin
          `rm -rf #{SecurityMopDir}` if File.exists?(SecurityMopDir)
          Dir.mkdirs(SecurityMopDir)
          `chmod a+rwx #{SecurityMopDir}`
          run['mops'] = [
            SecurityMopNil.instance,
            SecurityMop21.instance,
            SecurityMop22.instance,
            SecurityMop23.instance,
            SecurityMop2_4.instance,
            SecurityMop2_5.instance,
            SecurityMop2_6.instance
            ]
        rescue Exception => e
          logError e
          exit
        end
      end
    end

    class WaitForCalculationCompletion < Cougaar::Action
      def initialize(run, timeout=30.minutes)
        super(run)
        @timeout = timeout
      end

      def perform
        return if run['mops'] == nil
        endTime = Time.now + @timeout
        run['mops'].each do |mop|
          while !mop.isCalculationDone and Time.now <= endTime
            sleep 10.seconds
          end
        end
      end
    end


    class StartTcpCapture < Cougaar::Action
      attr_accessor :hostnames, :hosts, :agents

      def initialize(run, agents)
        super(run)
        @agents = agents
      end

      def perform
        SecurityMop23.instance.startTcpCapture(@agents)
      end
    end # class StartTcpCapture




    # Action which runs the six security mops every five minutes
    class InitiateSecurityMopCollection < Cougaar::Action
      attr_accessor :mops, :frequency, :thread

      def initialize(run, frequency=3.minutes)
        super(run)
        Cougaar.setRun(run)
        @frequency = frequency
        @thread = nil
        run['SecurityIsSetup'] = false
        run['SecurityIsCompleted'] = false
        UserClass.clearCache
      end

      def self.halt
        AbstractSecurityMop.halt = true
      end
      def self.halted?
        return AbstractSecurityMop.halt
      end
      def halted?
        return self.class.halted?
      end

      def perform
	# No fork; helps avoid timing problems
        AbstractSecurityMop.halt = false
	begin
	  self.performAction
	rescue Exception => e
	  logErrorMsg "Error in InitiateSecurityMopCollection perform: #{e.class}, #{e.message}"
	  logErrorMsg e.backtrace.join("\n")
	end

        # or run initiate in it's own thread so that other actions can get underway.
        #self.threadPerformAction
      end

      def performAction
        # give a little more time for the CA and user domain agents to get ready.
        # (this is necessary only when following UserManagerReady)
#        sleep 2.minutes unless $WasRunning

        # remove mop results dir.  will recreate in StopSecurityMopCollection
        `rm -rf #{SecurityMopDir}` if File.exists?(SecurityMopDir)

#        storeIdmefsForSecurityMop
#        setPolicies
#        SecurityMop2_4.instance.run = @run

        @mops = [SecurityMopNil.instance,
                SecurityMop21.instance, SecurityMop22.instance,
                SecurityMop23.instance, SecurityMop2_4.instance,
                SecurityMop2_5.instance, SecurityMop2_6.instance]

        run['mops'] = @mops

        logInfoMsg "Setting up Security MOPs" if $VerboseDebugging
        if true   # !$WasRunning
          @mops.each do |mop|
            logInfoMsg "Setting up #{mop.class.name}" if $VerboseDebugging
            begin
              mop.setup
            rescue Exception => e
              logError e
            end
          end
#          sleep 2.minutes
        else
          logInfoMsg "Not setting up security MOPs because the existing society should already be set up"
        end
        logInfoMsg "Security MOP setup is complete" if $VerboseDebugging

        firstTime = true
        @thread = Thread.new do
          while !halted? do
            puts "performing security mops" if $VerboseDebugging
            @mops.each do |mop|
              begin
                if firstTime or mop.doRunPeriodically
                  logInfoMsg "performing #{mop.class.name}" if $VerboseDebugging
                  break if halted? and !firstTime
                  mop.perform
                end
              rescue Exception => e
                logError e, "error in InitiateSecurityMopCollection's thread"
              end
            end
            puts "done performing this set of security mops" if $VerboseDebugging
            sleep @frequency unless halted?
            firstTime = false
          end
        end

        AbstractSecurityMop.waitForCompletion('CompletedMinimumUnauthorizedServletAttempts', 5.minutes)
        puts "security mops thread now completed" if $VerboseDebugging
      end
      
      # These are the policies needed by all the mops
      def setPolicies
=begin
        Util.modifyPolicy(ncaEnclave, '', '
Policy DamlBootPolicyNCAServletForRearPolicyAdmin = [
  A user in role RearPolicyAdministration can access a servlet named NCAServlets
]
')
=end
      end
      
      def stop
        if @thread
          @thread.stop
          @thread = nil
        end
      end
    end # class InitiateSecurityMopCollection




    class StopSecurityMopCollection < Cougaar::Action
      def perform
        # we need to block until this is completed -- otherwise stopsociety
        # might get called prior to completion
        performAction
      end

      def performAction
        logInfoMsg "Halting security MOPs" if $VerboseDebugging
        InitiateSecurityMopCollection.halt

        `rm -rf #{SecurityMopDir}` if File.exists?(SecurityMopDir)
        Dir.mkdirs(SecurityMopDir)
        #`chmod a+rwx #{SecurityMopDir}`

        mops = run['mops']
#        sleep 1.minutes
        logInfoMsg "Shutting down security MOPs" if $VerboseDebugging
        mops.each do |mop|
          begin
	    logInfoMsg "shutting down #{mop.class.name}" if $VerboseDebugging
            mop.shutdown
          rescue Exception => e
            logError e
          end
        end
#        sleep 1.minutes

         AbstractSecurityMop.waitForCompletion('MOP2.4 Performed Once')
        
        Thread.fork do
          calculate
        end
      end

      def calculate
#        result = ''
        mops = run['mops']
        mops.each do |mop|
          begin
	    logInfoMsg "calculating #{mop.class.name}" if $VerboseDebugging
            mop.calculate
          rescue Exception => e
            logError e
          end
        end
        retries=0
        begin
          mops.each do |mop|
            next if mop.class == SecurityMopNil
            startTime = Time.now
            while (!mop.isCalculationDone) do
              retries += 1
              break if Time.now - startTime > 30.minutes
              logInfoMsg "waiting for mop calculation in #{mop.class.name} (#{retries})" if $VerboseDebugging
              sleep 30.seconds
            end
#            result += "#{makeMopXml(mop)}\n"
          end
        rescue Exception => e
          logError e
        end

        AbstractSecurityMop.finished(StopSecurityMopCollection)
      end
    end




    class SendSecurityMopRequest < Cougaar::Action
      def perform
        # self.threadPerformAction
        performAction
      end

      def performAction
        logInfoMsg "Pre-processing security MOPs" if $VerboseDebugging
        # if InitiateSecurityMopCollection didn't complete, StopSecurityMopCollection would
        # have aborted and there is no reason to sit through a long timeout period.
        unless AbstractSecurityMop.waitForCompletion(StopSecurityMopCollection)
          logErrorMsg "Aborting SendSecurityMopRequest"
          return nil
        end
        mops = run['mops']

        mops.each do |mop|
          begin
	    logInfoMsg "postCalculating #{mop.class.name}" if $VerboseDebugging
            mop.postCalculate
          rescue Exception => e
            logError e
          end
        end

        result = ''
        mops.each do |mop|
          begin
            result += "#{makeMopXml(mop)}\n" unless mop.class == SecurityMopNil
          rescue Exception => e
            logError e, "Error in makeMopXml(#{mop.class.name})"
          end
        end

        logInfoMsg "num security mops: #{mops.size}" if $VerboseDebugging
        begin
          db = PStore.new(DbFilename)
          db.transaction do |db|
            db['pstoreVersion'] = 1.0
            db['datestring'] = "#{Time.now}"
            db['date'] = Time.now
            db['html'] = ''
            db['info'] = mops.collect {|mop| mop.info}
            db['summary'] = mops.collect {|mop| mop.summary}
            db['scores'] = mops.collect {|mop| mop.score}
            db['raw'] = mops.collect {|mop| mop.raw}
            db['supportingData'] = mops.collect {|mop| mop.supportingData}
            db.commit
          end
        rescue Exception => e
          logError e, "Error while creating security MOP pstore"
        end

html = ''
puts html if $VerboseDebugging
puts (mops.collect {|mop| mop.score}).inspect if $VerboseDebugging
        AbstractSecurityMop.finished(SendSecurityMopRequest)
        return html
      end

      def makeMopXml(mop)
        return '' if mop.class == SecurityMopNil
        mop.score = mop.score.round
        x = "<Report>\n"
        x +=  "<metric>MOP #{mop.name}</metric>\n"
        x +=  "<id>#{Time.now}</id>\n"
        x +=  "<description>#{mop.descript}</description>\n"
        x +=  "<score>#{mop.score}</score>\n"
        x +=  "<info><analysis><para>#{mop.info}</para></analysis></info>\n"
        x +="</Report>\n"
        return x
      end # makeMopXml
    end

  end # module Actions
end # module Cougaar

