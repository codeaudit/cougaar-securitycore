##
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

=begin

This file lays out the basic framework for running experiments.  There are two
classes in this framework, one for the experiment and one for the stress.

The experiment contains the global type information.  It has a reference
to all the stresses which should be run.  It is the controller of the test
(through the 'run' function).

The stress contains information associated with a particular test.  It may
include stresses or collection of information.  Any number of stresses may be
combined into an experiment and all run at the same time.

Both types of classes may have methods which are executed before or after
any of the actions or states (do_action or wait_for).

This is adds actions to the ACME framework.  The code written for the ACME
framework runs in the ACME lexical scope.  In contrast, all code written under this
framework runs in the scope of the class the code was written in -- a subclass of either
ExperimentFramework or StressFramework.

An experiment runs the actions and states set up via the 'do_action' and 'wait_for'
statements from the 'runScript' method called from ExperimentFramework.
For an example (and the default), see runScript.rb.

The concept of this framework is that experiments are identical except for
small additions before or after the actions and states.  The framework extends the
actions and states by calling a pre and post method around each.  For example,
if the runScript contains 'do_action "PublishGLSRoot"', then just prior to running
the perform method on PublishGLSRoot, the prePublishGLSRoot method will be called on
the AbstractExperimentFramework instance and on each of the AbstractStressFramework
instances, then the perform is executed, and finally the postPublishGLSRoot method
is called on each environment/experiment instance.

This is very similar to the GUI frameworks built for VB, C++, Java, Delphi, etc. where
a button has a set of events which it responds to.  If you want code associated with
a mouse_click, you add code for the mouse_click.

There are two classes:  ExperimentFramework and StressFramework.

The stress instance will typically contain the requested stresses.  The experiment contains one
or more stresses, and is the controller of the test.  Combinations of stresses
are a simple matter of loading the necessary experiment files and listing them.

The stresses may occur in either the environment or the experiments; however, because of
the capability of combining stresses, not experiments, it will generally make
more sense to put all stresses in the experiments.
=end


require 'cougaar/scripting'
require 'ultralog/scripting'
require 'timeout'

class ExperimentFramework
  include Cougaar
  include UltraLog
  
  attr_accessor  :stresses, :name, :run
  
  def initialize(name=nil, stresses=[])
    super()
    if name
      @name = name
      $ExperimentName = name unless $ExperimentName
      $ExperimentClass = name unless $ExperimentClass
      $Stresses = stresses unless $Stresses
    end
    @stresses = stresses
  end
  
  def initializeStresses
    # We need stress instances. If we have classes, create an instance.
    @stresses = @stresses.collect do |stress|
      stress = stress.new if stress.kind_of?(Class)
      stress.myexperiment = self
      stress
    end
  end
  
  def doExperimentMethod(method, *args)
    self.send(method, *args) if self.respond_to? method
    if $RunStressesInParallel and @stresses.size>1
      threads = []
      @stresses.each do |x|
        if x.respond_to? method
          threads << Thread.fork do
            begin
              x.send(method, *args)
            rescue => e
              puts "#{e.class.name}: #{e.message}"
              puts e.backtrace.join("\n")
              raise e
            end
          end
        end
      end
      begin
        status = timeout($MaxTimeToApplyStress) {
          threads.each {|thread| thread.join}
        }
      rescue TimeoutError => ex
        logWarningMsg "Stresses took too much time to execute"
        logWarningMsg "Leaving stresses running but going to next stage anyway"
        threads.each { |thread|
          if thread.alive?
            logWarningMsg "Thread #{thread} is still alive - thread status:#{thread.status}"
            #Thread.kill (thread)
          end
        }
      end
    else
      @stresses.each {|x| x.send(method, *args) if x.respond_to?(method)}
    end
  end
  
  # Set up a default method
  def postStopSociety
    printSummary
  end
end # class ExperimentFramework

##########################################################

class StressFramework
  include Cougaar
  include UltraLog
  
  attr_accessor :myexperiment
  
  def run
    @myexperiment.run
  end
end

##########################################################

# Create the 'Call' action
module Cougaar
  module Actions
    class Call < Cougaar::Action
      def initialize(run, methodName, *args)
        super(run)
        @methodName = methodName
        @args = args
      end
      def perform
        #logInfoMsg "  INFO: #{@methodName}"
        logInfoMsg "#{@methodName}"
        @run.myexperiment.doExperimentMethod @methodName, *@args
      end
    end
  end
end
