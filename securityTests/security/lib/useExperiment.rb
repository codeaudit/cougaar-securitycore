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

# these allow the 'run' and 'myexperiment' to be used outside the Run
# and ExperimentFramework classes.
def getRun
#  Cougaar::Run.myrun
  Cougaar.getRun
end
def setRun(run)
#  Cougaar::Run.myrun = run
  Cougaar.setRun(run)
end
def getMyExperiment
  Cougaar::Run.myexperiment
end

module Cougaar
  class Run
=begin
    def self.myrun
      @@myrun
    end
    def self.myrun=(aRun)
      @@myrun = aRun
    end
=end
    def self.myexperiment
      @@myexperiment
    end
    def myexperiment=(exp)
      @@myexperiment = exp
      setRun(self)
      @myexperiment = exp
    end
    def myexperiment
      @myexperiment
    end
  end
  
  module Actions
    class UseExperiment < Cougaar::Action
      DOCUMENTATION = Cougaar.document {
        @description = "Loads the experiment class specified by the parameter."
        @example = "do_action LoadExperiment, 'Security1a'"
      }
      def initialize(run, experimentClass)
        super(run)
        # If is a string, get the associated class.
        if experimentClass.kind_of?(String)
          @experimentClass = eval(experimentClass)
        else
          @experimentClass = experimentClass
        end
      end
      def perform
        # Unless we are holding an object,  instantiate a new object.
        if @experimentClass.kind_of?(Class)
          myexperiment = @experimentClass.new
        else
          myexperiment = @experimentClass
        end
        run.myexperiment = myexperiment
        myexperiment.run = @run
        myexperiment.initializeStresses
      end
    end
    
    class MakeExperiment < UseExperiment
      DOCUMENTATION = Cougaar.document {
        @description = "Makes and uses an experiment with specified name and stresses."
        @example = "do_action 'MakeExperiment', 'ExperimentClassName', [Stress1, Stress2]"
      }
      def initialize(run, experimentName, stresses)
        experiment = ExperimentFramework.new experimentName, stresses
        super(run, experiment)
      end
    end
  end
end
