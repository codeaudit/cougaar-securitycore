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
        AbstractSecurityMop.halt = false
        @frequency = frequency
        @thread = nil
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
        # give a little more time for the CA and user domain agents to get ready.
        sleep 2.minutes unless $WasRunning

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

        puts "setting up" if $VerboseDebugging
        if false # $WasRunning
          logInfoMsg "Not setting up security MOPs because the existing society should already be set up"
        else
          @mops.each do |mop|
            logInfoMsg "Setting up #{mop.class.name}" if $VerboseDebugging
            begin
              mop.setup
            rescue Exception => e
              logError e
            end
          end
          sleep 2.minutes
        end

        firstTime = true
        @thread = Thread.new do
          while !halted? do
            puts "performing security mops" if $VerboseDebugging
            @mops.each do |mop|
              begin
                puts "performing #{mop.class.name}" if $VerboseDebugging
                break if halted?
                mop.perform if firstTime or mop.doRunPeriodically
              rescue Exception => e
                logError e, "error in InitiateSecurityMopCollection's thread"
              end
            end
            puts "done performing this set of security mops" if $VerboseDebugging
            sleep @frequency unless halted?
            firstTime = false
          end
        end
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
        `rm -rf #{SecurityMopDir}` if File.exists?(SecurityMopDir)
        Dir.mkdirs(SecurityMopDir)
        `chmod a+rwx #{SecurityMopDir}`
        logInfoMsg "Halting security MOPs" if $VerboseDebugging
        mops = run['mops']
        InitiateSecurityMopCollection.halt
        sleep 1.minutes
        logInfoMsg "Shutting down security MOPs" if $VerboseDebugging
        mops.each do |mop|
          begin
	    logInfoMsg "shutting down #{mop.class.name}" if $VerboseDebugging
            mop.shutdown
          rescue Exception => e
            logError e
          end
        end
        sleep 1.minutes
      end
    end




    class SendSecurityMopRequest < Cougaar::Action
      def perform
        logInfoMsg "Pre-processing security MOPs" if $VerboseDebugging
        mops = run['mops']
        result = ''
        mops.each do |mop|
          begin
	    logInfoMsg "calculating #{mop.class.name}" if $VerboseDebugging
            mop.calculate
          rescue Exception => e
            logError e
          end
        end
        retries=50
begin
        mops.each do |mop|
          startTime = Time.now
          while (!mop.isCalculationDone) do
            retries -= 1
            break if Time.now - startTime > 5.minutes
            puts "waiting for mop calculation in #{mop.class.name} (#{retries})" if $VerboseDebugging
            sleep 30.seconds
          end
          result += "#{makeMopXml(mop)}\n"
        end
rescue Exception => e
 logError e
end
        mops.each do |mop|
          begin
	    logInfoMsg "postCalculating #{mop.class.name}" if $VerboseDebugging
            mop.postCalculate
          rescue Exception => e
            logError e
          end
        end

#        html = (mops.collect {|mop| makeMopXml(mop)}).join("\n")

        logInfoMsg "num security mops: #{mops.size}" if $VerboseDebugging

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

html = ''
puts html if $VerboseDebugging
puts (mops.collect {|mop| mop.score}).inspect if $VerboseDebugging
        return html
      end

      def makeMopXml(mop)
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

