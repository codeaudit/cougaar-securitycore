#
#  <copyright>
#  Copyright 2003 SRI International
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#

require 'thread'
require 'ftools'
require 'framework/scripting'
require 'framework/securityMop2.4'
require 'pstore'

SecurityMopDir = "#{ENV['CIP']}/workspace/security/mops"
DbFilename = "#{SecurityMopDir}/mops"

class AccessAttempt
  attr_accessor :attempt
  def initialize(attempt)
    @attempt = attempt
  end
end


module Cougaar
  module Actions

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
            mop.shutdown
          rescue Exception => e
            logInfoMsg "WARNING: Error while shutting down #{mop.class}, #{e.class} #{e.message}"
            puts e.backtrace.join("\n")
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
        mops.each {|mop| mop.calculate}
        retries=50
        mops.each do |mop|
          startTime = Time.now
          while (!mop.calculationDone) do
            retries -= 1
            break if Time.now - startTime > 5.minutes
            puts "waiting for mop calculation in #{mop.class.name} (#{retries})" if $VerboseDebugging
            sleep 30.seconds
          end
          result += "#{makeMopXml(mop)}\n"
        end

#        html = (mops.collect {|mop| makeMopXml(mop)}).join("\n")

logInfoMsg "num security mops: #{mops.size}" if $VerboseDebugging

        db = PStore.new(DbFilename)
        db.transaction do |db|
          db['datestring'] = "#{Time.now}"
          db['date'] = Time.now
          db['html'] = ''
          db['info'] = mops.collect {|mop| mop.info}
          db['summary'] = mops.collect {|mop| mop.summary}
          db['scores'] = mops.collect {|mop| mop.score}
          db['raw'] = mops.collect {|mop| mop.raw}
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



  
    # Action which runs the six security mops every five minutes
    class InitiateSecurityMopCollection < Cougaar::Action
      attr_accessor :mops, :frequency, :thread
      @@halt = false
      def initialize(run, frequency=3.minutes)
        super(run)
        Cougaar.setRun(run)
        @@halt = false
        @frequency = frequency
        @thread = nil
        UserClass.clearCache
      end

      def self.halt
puts "halting security mops" if $VerboseDebugging
        @@halt = true
      end
      def self.halted?
        return @@halt
      end
      def halted?
        return @@halt
      end
      
      def perform
        # give a little more time for the CA and user domain agents to get ready.
        sleep 2.minutes unless $WasRunning

        # remove mop results dir.  will recreate in StopSecurityMopCollection
        `rm -rf #{SecurityMopDir}` if File.exists?(SecurityMopDir)

#        storeIdmefsForSecurityMop
#        setPolicies
#        SecurityMop2_4.instance.run = @run

        @mops = [SecurityMop2_1.instance, SecurityMop2_2.instance,
                SecurityMop2_3.instance, SecurityMop2_4.instance,
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
              logInfoMsg "WARNING: Error #{e.class} (#{e.message}) while setting up #{mop.class}"
              puts e.backtrace.join("\n")
            end
          end
          sleep 2.minutes
        end

        @thread = Thread.new do
          while !halted? do
            puts "performing security mops" if $VerboseDebugging
            @mops.each do |mop|
              begin
                puts "performing #{mop.class.name}" if $VerboseDebugging
                break if halted?
                mop.perform
              rescue Exception => e
                puts "error in InitiateSecurityMopCollection's thread"
                puts "#{e.class}: #{e.message}"
                puts e.backtrace.join("\n")
              end
            end
            puts "done performing this set of security mops" if $VerboseDebugging
            sleep @frequency unless halted?
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
  end # module Actions
end # module Cougaar




class Object
  # Ideally, the objects saved with this method will not be very deep.
  def saveForSecurityMop(filename=File.join($CIP, "workspace", "log4jlogs", "securityMop"))
    ensureSecurityMopSaverMutex
    @securityMopSaverMutex.synchronize do
      File.open(filename, 'a') do |file|
        Marshal.dump([Time.now, self], file)
      end
    end
  end
  def ensureSecurityMopSaverMutex
    @securityMopSaverMutex = Mutex.new unless @securityMopSaverMutex
  end
end



def storeIdmefsForSecurityMop
  if @idmefStorerRunCount != getRun.count
    begin
      @idmefStorerListener.close if @idmefStorerListener
    rescue Exception => e
      logWarningMsg "Couldn't close existing idmefStorerListener"
      puts "#{e.class}: #{e.message}"
      puts e.backtrace.join("\n")
    end
    @idmefStorerListener = nil
  end
  unless @idmefStorerListener
    idmefStorerRunCount = getRun.count
    @idmefStorerListener = onCaptureIdmefs do |event|
      puts 'saving event' if $VerboseDebugging
      event.saveForSecurityMop
    end
  end
end
