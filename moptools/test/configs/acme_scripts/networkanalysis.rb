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
                    def initialize(run, hostname)
                                super(run)
                                @hostname = hostname
                                @run = run
                     end
                     def perform
                        #get list of nfs hosts
                        nfsHosts=[]
                        @run.society.each_host do |host|
				puts "HOST #{host.name}"
                        	host.each_facet do |facet|
					valuelist =facet.[]("service")
					if not valuelist.nil?  
					valuelist.each{|facetvalue|
						if facetvalue=="nfs-software" or facetvalue=="nfs-shared" or facetvalue=="NFS" or facetvalue="nfs"
						inlist = "FALSE"
						nfsHosts.each{ |nhost|
							if nhost==host.name
				  				inlist="TRUE" 
							end 
						}		
						if inlist=="FALSE"			
							nfsHosts.push("#{host.name}")
						end
						end
					}		
					end		  
				 end
                        end
			nfsHosts.each{|nhost|
				puts "NFS HOST:#{nhost}"
			}
                        outputfilename="#{@run.name}_analysis.in"
                        puts "Output of raw network data #{outputfilename}"
                        puts "Removing old file if present"
                        commandsyntax="ssh #{@hostname} ./runTethereal.sh #{outputfilename}"
			nfsHosts.each{|nhost|
				commandsyntax = "#{commandsyntax} #{nhost}"
			}
                        puts "Executing #{commandsyntax}"
                        $pid = fork{
                                 puts "Executing #{commandsyntax}"
                                 exec(commandsyntax)
                        }
                        puts "PID: #{$pid}"
                     end
                end

                class StopEtherealAnalysis  < Cougaar::Action
                     def initialize(run, hostname)
                                super(run)
                                @hostname = hostname
                                @run = run
                     end
                     def perform
                        system "ssh -t #{@hostname} ./stopTehtereal"
                        infile="#{@run.name}_analysis.in"
                        outfile="#{@run.name}_analysis.out"
                        puts "Analyze file: #{infile}"
                        puts "Create file: #{outfile}"
                        commandsyntax="ssh -t #{@hostname} ./readTethreal.sh #{infile} #{outfile}"
                        exec(commandsyntax)
                        puts "Output written to #{outfile} on #{@hostname}"
                     end
                end
        
        end
end
