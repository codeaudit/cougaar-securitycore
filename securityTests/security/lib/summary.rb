=begin
This code provides for saving summary messages during the course of the experiment which may be re-printed at the end.  Very often the core messages are lost in the deluge of diagnostic messages.  This is intended to remedy this problem.
=end

#puts "in summary"
#exit

#class AbstractExperimentFramework
   def summary(msg)
      ensureSummaryMsgs
      logInfoMsg msg
      $SummaryMsgs << msg
   end

   def printSummary
      ensureSummaryMsgs
      if $SummaryMsgs.size > 0
         logInfoMsg
         logInfoMsg '---------- Summary ---------'
         $SummaryMsgs.each do |msg|
            logInfoMsg msg
         end
         logInfoMsg '----------------------------'
      else
         logInfoMsg 'no summary'
      end
   end

   def ensureSummaryMsgs
      $SummaryMsgs = [] unless $SummaryMsgs
   end

   def clearSummaryMsgs
      $SummaryMsgs = []
   end

#end

=begin
class AbstractStressFramework
   def summary(msg)
      env.summary msg
   end
   # Note: you shouldn't print the summary messages from the experiment because
   #   when multiple experiments are combined into one environment, you may end
   #   up printing the summary more than once.
end
=end
