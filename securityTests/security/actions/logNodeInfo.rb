require 'security/lib/scripting.rb'

module Cougaar
  module Actions
      class LogNodeInfo < Cougaar::Action
        # By default, we retrieve the process info every 60 seconds.
        # However, the action can take two additional parameters which allows
        # to get the process info faster on one specific node.
        def initialize(run, nodename=nil, frequency=5.seconds, getStackTrace=true)
          super(run)
          @nodename = nodename
          @frequency = frequency
          @getStackTrace = getStackTrace
          @nodeInfoMap = {}
          dirname = "#{CIP}/workspace/test"
          Dir.mkdir("#{CIP}/workspace") unless File.exist?("#{CIP}/workspace")
          Dir.mkdir("#{dirname}")  unless File.exist?("#{dirname}")
          @filename="#{dirname}/node_info.log"
	  Cougaar::Actions::Stressors.addStressIds(['processInfo'])
	  logInfoMsg "Saving process info to #{@filename}"
        end   
        
        def perform()
	  logInfoMsg "Perform - Saving process info to #{@filename}"
          @nodeInfoFile = File.new(@filename, File::RDWR | File::APPEND | File::CREAT)
          # Dump a header string
	  @nodeInfoFile << "#{NodeInfo.header_string()}\n"
	  @nodeInfoFile.flush
	  getNodePids()
	  #@nodeInfoFile.close
        end
        
        def getNodePids
          Thread.fork {
	    sleep_time = 10.seconds
            begin
	      while (true)
                #logInfoMsg "Searching for node Java pids..."
		# Not all nodes may be started, so we need to periodically
		# check for new nodes. Also, some nodes may die.
		@run.society.each_service_host("acme") { |host|
                  #logInfoMsg "Searching for node Java pids: #{host.name}"
		  response = @run.comms.new_message(host).set_body("command[list_java_pids]").request(300)
		  if (response != nil)
		    parsePids(response.body).each { |node, pid|
		      #logInfoMsg "getNodePid: #{node}: #{host.name} - #{pid}"
                      if !@nodeInfoMap.has_key?(node)
		        nodeInfo = NodeInfo.new(node, host, pid)
		        getParam(nodeInfo, "-Xmx")		    
		        @nodeInfoMap[node] = nodeInfo
	                getMemoryUsage(nodeInfo)
                      end
		    }
		  end
		}
		sleep sleep_time
		sleep_time = sleep_time * 2
	      end
            rescue => e
              @run.error_message "Unable to perform LogNodeInfo action"
              @run.error_message "#{e.message}\n#{e.backtrace.join("\n")}"
            end
	  }        
        end
        # response should be in the format:
        #
        #<message type="chat" to="acme_console@peach/expt-lemon-ASMT-PING-1-1of1">
        # <thread>JRT_ebede31c4d9bc957372a</thread>
        # <body>CA-NODE=11963,MGMT-NODE=12062</body>
        #</message>
        #
        # str should be of this format:
        #
        # <node>=<java_pid>[, <node>=<java_pid>]+
        def parsePids(str)
          #@run.info_message "Response from #{host.name} #{response.body}"
          pidmap = {}
          if (str != nil) 
            str.split(',').each { |i|
              i.scan(/(.+)=(.+)/) { |match|
                pidmap[match[0]] = match[1]
              }
            }
          end
          return pidmap
        end

        def getMemoryUsage(nodeInfo)
	    # Doing the rexec takes a long time, so we launch one thread per host
	    # to parallelize the actions.
	    Thread.fork() {
	      sleep_time = 60.seconds
              if (@nodename != nil && nodeInfo.name == @nodename)
	        sleep_time = @frequency
              end
              #logInfoMsg "Monitoring #{nodeInfo.name} - pid=#{nodeInfo.pid} at f=#{sleep_time} - #{nodeInfo.host.name}"
              while (true)
	        begin
		  # -h   Do not display header
		  # -p   Display info for specified PID
		  # -o   output display
		  command = "ps -h -p #{nodeInfo.pid} -o pcpu,pmem,sz,rss,rsz"
		  #saveAssertion "processInfo", "#{nodeInfo.host.name} #{command}"
		  response = @run.comms.new_message(nodeInfo.host).set_body("command[rexec]#{command}").request(300)
                  #logInfoMsg response
                  gotResults = false
                  if (response != nil)
                    gotResults = true
                    parseMemoryUsage(nodeInfo, response.body)
                  end
                  #logInfoMsg "logNodeInfo1?: #{gotResults}"
                  if (@nodename != nil && nodeInfo.name == @nodename && @getStackTrace)
                    command = "kill -QUIT #{nodeInfo.pid}"
                    #puts "Send QUIT signal :#{command} ..."
                    # `date > #{CIP}/workspace/nodelogs/#{nodename}.log`
		    res = @run.comms.new_message(nodeInfo.host).set_body("command[rexec]#{command}").request(300)
                    #puts "Done Send QUIT signal :#{res}"
                  end

                  # Get load information
                  command = "uptime"
		  response = @run.comms.new_message(nodeInfo.host).set_body("command[rexec]#{command}").request(300)
                  if (response != nil)
                    gotResults = true
                    parseUpTime(nodeInfo, response.body)
                  end
                  #logInfoMsg "logNodeInfo2?: #{gotResults}"
                  if (gotResults)
		    logNodeInfo(nodeInfo)
                  end
	        rescue => e
	  	  saveAssertion "processInfo", "Unable to get process info: #{e.message}\n#{e.backtrace.join("\n")}"
	        end
		sleep sleep_time
              end # while
	    }
        end
              
        def getParam(nodeInfo, param)
	  @run.society.each_node { |node|
	    if nodeInfo.name == node.name
	      node.parameters.each { |p|
		#saveAssertion "processInfo", p
		p.scan(/-Xmx(.+)/) { |match|
		  nodeInfo.xmx = match[0]
		  break
		}
	      }
	    end
	    if nodeInfo.xmx != nil
	      break
	    end
	  }
        end

        #
        # str should be in the following format:
        # VSZ\n
        # 111111
        #
        def parseMemoryUsage(nodeInfo, str)
	  #saveAssertion "processInfo", str
	  b = str.scan(/[\w\.]+/)
	  nodeInfo.pcpu = b[0]
	  nodeInfo.pmem = b[1]
	  nodeInfo.rss = b[3]
	  nodeInfo.rsz = b[4]
        end

        def parseUpTime(nodeInfo, str)
          str.scan(/load average: (.+),\s+(.+),\s+(.+)/) { |match|
            nodeInfo.load1min = match[0]
            nodeInfo.load5min = match[1]
            nodeInfo.load15min = match[2]
          }
        end
 
        def logNodeInfo(nodeInfo)
          #logInfoMsg "Saving data to disk... #{nodeInfo != nil}"
          if (nodeInfo != nil) 
            @nodeInfoFile << "#{nodeInfo.to_s}\n"
	    @nodeInfoFile.flush
          end
        end
      end # LogNodeInfo
      
      # data object for NodeInfo
      class NodeInfo 
        
        attr_reader :name, :host, :pid
        attr_accessor :xmx, :pcpu, :pmem, :rss, :rsz, :load1min, :load5min, :load15min
        
        def initialize(name, host, pid, xmx=nil)
          @name = name
          @host = host
          @pid = pid
          @xmx = xmx
        end

        def NodeInfo.header_string
          #      "05/13/2004 13:51:24 u129            16434  ROOT-CA-NODE                         1"
	  return "Host            PID    Date       Time     Node_Name                            RSZ\tXMX\tDIFF\tPCPU\tPMEM\tRSS\tL1\tL5\tL15"
        end
       
        def to_s
	  now = Time.new
          s = "#{@host.name.ljust(15)} #{@pid.ljust(6)} "
          s += "#{now.strftime("%m/%d/%Y")} #{now.strftime("%H:%M:%S")} "
          s += "#{name.ljust(30)}\t#{rsz}\t"
          value = @xmx
          if (@xmx != nil) 
            @xmx.scan(/([0-9]+)(.+)/) { |match|
              value = match[0].to_i
              unit = match[1].downcase
              if (unit =~ /m/)
                value = value * 1024
              elsif (unit =~ /g/)
                value = value * 1024 * 1024
              elsif (unit =~ /k/)
                value = value
              end
            }
          else
            value = 0
          end
          # Compute diff between XMX and RSZ
          diff = value.to_i - rsz.to_i
          s += "#{value}\t#{diff}\t#{pcpu}\t#{pmem}\t#{rss}"
          s += "\t#{load1min}\t#{load5min}\t#{load15min}"
        end
        
      end # end class NodeInfo
   end
end
