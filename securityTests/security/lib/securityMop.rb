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
require 'security/lib/scripting'
#require 'security/lib/securityMop2.4'
require 'pstore'


class AccessAttempt
  attr_accessor :attempt
  def initialize(attempt)
    @attempt = attempt
  end
end


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
  if @idmefStorerRunCount != run.count
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
    idmefStorerRunCount = run.count
    @idmefStorerListener = onCaptureIdmefs do |event|
      puts 'saving event' if $VerboseDebugging
      event.saveForSecurityMop
    end
  end
end
