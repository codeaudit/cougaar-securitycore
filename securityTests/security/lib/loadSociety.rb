#
#  <copyright>
#  Copyright 2003 SRI International
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
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
   
    class SetRunId < Cougaar::Action
      def initialize(run)
        super(run)
        Cougaar.setRun(run)
      end
      def perform
      end
    end
 
    class LoadSociety < Cougaar::Action
      RESULTANT_STATE = "SocietyLoaded"
      def initialize(run, loadFromFileType, societyFilename, layoutFilename,
                     transformSocietyArgs, transformCommunityArgs)
        super(run)
        Cougaar.setRun(run)
        @loadFromFileType = loadFromFileType
        @societyFilename = societyFilename
        @layoutFilename = layoutFilename
        @transformSocietyArgs = transformSocietyArgs
        @transformCommunityArgs = transformCommunityArgs
      end
      
      def perform
        loadSociety
        layoutSociety
        transformSociety
        transformCommunity
      end
      
      def loadSociety
        case @loadFromFileType
        when 'csmart'
          run.do_action "LoadSocietyFromCSmart", @societyFilename,
          $CsmartHost,
          $CsmartUsername,
          $CsmartPassword,
          $CsmartDB
        when 'xml'
          run.do_action "LoadSocietyFromXML", @societyFilename
        when 'script'
          run.do_action "LoadSocietyFromScript", @societyFilename
        else
          criticalError "The variable '@loadFromFileType' contains an unknown value: #{@loadFromFileType}."
        end
      end
      
      def layoutSociety
        if @layoutFilename
          run.do_action 'Call', 'preLayoutSociety'
          run.do_action 'LayoutSociety', *@layoutFilename
          run.do_action 'Call', 'postLayoutSociety'
        end
      end
      
      def transformSociety
        if @transformSocietyArgs
          run.do_action "Call", "preTransformSociety"
          if @transformSocietyArgs
            run.send :do_action, "TransformSociety", *@transformSocietyArgs
          end
          run.do_action "Call", "postTransformSociety"
        end
      end
      
      def transformCommunity
        if @transformCommunityArgs
          run.do_action "Call", "preTransformCommunity"
          if @transformSocietyArgs
            run.send :do_action, "TransformSociety", *@transformCommunityArgs
          end
          run.do_action "Call", "postTransformCommunity"
        end
      end
    end
    
    class ConditionalStartSociety < StartSociety
      RESULTANT_STATE = "SocietyRunning"
      def initialize(run, timeout=120, debug=false)
        super(run, timeout, debug)
        @timeout = timeout
        @debug = debug
      end
      def perform
        puts "--------- in ConditionalStartSociety ---------"
        if $WasRunning
          logInfoMsg
          logInfoMsg "Society was already running, will use it ..."
          logInfoMsg
        else
          @run.do_action "Call", "preStartSociety"
          @run.do_action "StartSociety", @timeout, @debug
          @run.do_action "Call", "postStartSociety"
        end
      end
    end
    
    class DetermineIfSocietyRunning < Cougaar::Action
      RESULTANT_STATE = "SocietyRunning"
      def initialize(run, timeout=120, debug=false)
        super(run)
        @timeout = timeout
        @debug = debug
      end
      def perform
        begin
          url = @run.society.agents['NCA'].uri
          url = url[0..(url.index('$')-1)]
          puts "in determine: url='#{url}'" if $VerboseDebugging
          $WasRunning = getHtml(url, 2.minutes)
	  puts "$WasRunning = #{$WasRunning}"
          if $WasRunning
            unless $WasRunning.status==200
              puts "$WasRunning.status=#{$WasRunning.status.inspect}, setting to false"
              $WasRunning = false
            end
          else
            $WasRunning = false
          end
          logInfoMsg "$WasRunning = #{$WasRunning}"
        rescue Exception
          puts 'setting $WasRunning to false'
          $WasRunning = false
        end
      end
    end
    
    class ConditionalCleanupSociety < Cougaar::Action
      def perform
        if $CleanupSociety and not $WasRunning
          run.do_action "Call", "preCleanupSociety"
          run.do_action "CleanupSociety"
          run.do_action "Call", "postCleanupSociety"
        end
      end
    end
    
  end # module Actions
  
  
  
  module States
    
    class ConditionalGLSConnection < Cougaar::State
      def initialize(run, await_oplan=true, timeout=nil, &block)
        super(run, timeout, &block)
        @await_oplan = await_oplan
        @timeout = timeout
        @block = block
      end
      def process
        unless $WasRunning
          run.wait_for "GLSConnection", @await_oplan, @timeout, &@block
          
        else
          puts 'emptying nextoplanstage.process'
          run['gls_client'] = UltraLog::GLSClient.new(run)
          eval "
module Cougaar
  module States
    class NextOPlanStage
      def process
         logInfoMsg 'Since the society was already running, NextOPlanStage is being skipped.'
      end
    end
  end
end"
        end
      end
    end
    
    class ConditionalNextOPlanStage < Cougaar::State
      def initialize(run, timeout=nil, &block)
        super(run, timeout, &block)
        run.wait_for "NextOPlanStage", timeout, &block
      end
      def process
      end
    end
    
    
  end # module States


=begin
  class Run
    def do_action_now(
      r = Cougaar::Run.new(1,
=end      

end # module Cougaar
