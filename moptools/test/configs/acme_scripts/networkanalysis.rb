#Cougaar Actions to Start and Stop analysis of network traffic
#
#	Action StartEtherealAnalysis start tethereal and dumps the results to a file.
#
#	Action StopEtherealAnalysis stops the process created by executing tethereal.
#	The process id is stored in the global variable $pid.	Next, tetheral is run 
#	again to analyze the results and dump them into another file. 
#
#
module Cougaar
  module Actions
    class StartEtherealAnalysis < Cougaar::Action
      def initialize(run)
        super(run)
        @run = run
      end
      def perform
        outputfilename="#{@run.name}_analysis.in"
        puts "Output of raw network data #{outputfilename}"
        puts "Removing old file if present"
        system "rm -f #{outputfilename}"
        commandsyntax="tethereal -z io,phs -w #{outputfilename}"
	puts "Executing #{commandsyntax}"
	$pid = fork{
	  puts "Executing #{commandsyntax}"
	  exec(commandsyntax)
	}
	puts "PID: #{$pid}"
      end
    end

    class StopEtherealAnalysis  < Cougaar::Action
      def initialize(run)
	super(run)
	@run = run
      end
      def perform
	system "kill #{$pid}"
	infile="#{@run.name}_analysis.in"
	outfile="#{@run.name}_analysis.out"
	puts "Analyze file: #{infile}"
	puts "Create file: #{outfile}"
	commandsyntax="ethereal -r #{infile} -w #{outfile}"
	exec(commandsyntax)
	puts "Output written to #{outfile}"
      end
    end
    
  end
end
