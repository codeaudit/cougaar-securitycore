##
#  <copyright>
#  Copyright 2002 System/Technology Devlopment Corp.
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

module Cougaar

  module Actions

    class DefineLinksInK < Cougaar::Action
      def initialize(run, links)
        super(run)
        @links = links
      end
      def perform
        @links.each do |link| 
          @run.do_action "DefineWANLink", link[:name], link[:src], link[:dest]
        end
      end
    end

    class DegradeKs < Cougaar::Action
      def initialize(run, links)
        super(run)
        @links = links
      end
      def perform
        @links.each do |link| 
          if link[:set_speed] == "0"
            @run.do_action "DisableWANLink", link[:name]
          else
            @run.do_action "SetBandwidth", link[:name], link[:set_speed]
          end
        end
      end
    end

    class ResetDegradeKs < Cougaar::Action
      def initialize(run, links)
        super(run)
        @links = links
      end
      def perform
        @links.each do |link| 
          if link[:set_speed] == "0"
            @run.do_action "RenableWANLink", link[:name]
          else
            @run.do_action "SetBandwidth", link[:name], link[:max_speed]
          end
        end
      end
    end

    class CyclicDegradeKs < Cougaar::Action
      def initialize(run, on_time, off_time, links)
        super(run)
        @on_time = on_time
        @off_time = off_time
        @links = links
      end
      def perform
        @links.each do |link| 
          @run.do_action "StartIntermitWANLink", link[:name], @on_time, @off_time
        end
      end
    end

    class ResetCyclicDegradeKs < Cougaar::Action
      def initialize(run, links)
        super(run)
        @links = links
      end
      def perform
        @links.each do |link| 
          @run.do_action "StopIntermitWANLink", link[:name]
        end
      end
    end

  end

end
