require "security/lib/cougaarMods"

module Cougaar
  module Actions
    class LogMessageQueue < Cougaar::Action
  
      def initialize(run,interval = 1.minutes )
        super(run)
        @run=run
        @sleepInterval=interval
        @dirname = "#{CIP}/workspace/test/message_queue_log"
        Dir.mkdir("#{CIP}/workspace") unless File.exist?("#{CIP}/workspace")
        Dir.mkdir("#{@dirname}")  unless File.exist?("#{@dirname}")
        @nodefilename = Hash.new()
        @parturl="/message/queues?frame=dataFrame&agent=*"
        logInfoMsg "initialize LogMessageQueue done"
        Cougaar::Actions::Stressors.addStressIds(['LogMessageQueue'])
        #puts "initialize LogMessageQueue done"
      end
   

      def perform
        @run.society.each_node do |node|
          filename = "#{@dirname}/#{node.name}.log"
          file = File.new("#{filename}", File::RDWR | File::APPEND | File::CREAT) 
          #logInfoMsg "Created file : #{file}"
          @nodefilename["#{node.name}"] = file
          #logInfoMsg "node #{node.name}"
          startMonitoring node
        end
      end
      
      def startMonitoring node
        begin 
          Thread.fork {
            #logInfoMsg " Thread started for node -->#{node.name}"
            loop = true
            myfile = @nodefilename["#{node.name}"]
            myfile << "<HTML><HEAD> <TITLE> Message Queue Logs for #{node.name} </TITLE> </HEAD><BODY>"
            #logInfoMsg "gotfile #{myfile}"
            url="#{node.uri}/$#{node.name}#{@parturl}"
            while true
              result = Cougaar::Communications::HTTP.get(url)
              #logInfoMsg "Result before procesing : #{result}"
              processedresult = stripHtmltags (result.to_s)
              #logInfoMsg "Result received --> #{processedresult}"
              myfile << "#{processedresult} "
              sleep @sleepInterval
              loop = false
            end
          }
        rescue Exception => e
          logInfoMsg "error in LogMessageQueue startMonitoring  "
          logInfoMsg "#{e.class}: #{e.message}"
          logInfoMsg e.backtrace.join("\n")
        end
      end
      
      def stripHtmltags receivedhtml
        result = receivedhtml
        #logInfoMsg " stripHtmltags called with #{result}"
        stripedhtml = result.gsub(/<html><head><title>MTS Queues<\/title><\/head><body>/i,"")
        result = stripedhtml.to_s
        #logInfoMsg " result after first strip #{result}"
        stripedhtml = result.gsub(/<\/body>/i,"")
        result = stripedhtml.to_s
        #logInfoMsg " result after second strip #{result}"
        stripedhtml = result.gsub(/<\/html>/i,"")
        result = stripedhtml.to_s
        #logInfoMsg " result before return  #{result}"
        #logInfoMsg " returning #{stripedhtml}"
        return result
      end
      
    end
  end # module Action
end # module Cougaar
