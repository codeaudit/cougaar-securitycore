module Cougaar
  module Actions
      class LogNodeInfo < Cougaar::Action
        def initialize(run, args=nil)
          super(run)
          @args = args
          @nodeInfoMap = {}
          @filename="#{CIP}/workspace/test/node_info.log"
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
          Thread.fork {
            begin
	      sleep_time = 30.seconds
	      while true
		getMemoryUsage()
		sleep sleep_time
	      end
            rescue => e
              @run.error_message "Unable to perform LogNodeInfo action"
              @run.error_message "#{e.message}\n#{e.backtrace.join("\n")}"
            end
	    @nodeInfoFile.close
          }                    
        end
        
        def getNodePids
          Thread.fork {
	    sleep_time = 10.seconds
            begin
	      while (true)
		# Not all nodes may be started, so we need to periodically
		# check for new nodes. Also, some nodes may die.
		@run.society.each_service_host("acme") { |host|
		  response = @run.comms.new_message(host).set_body("command[list_java_pids]").request(30)
		  if (response != nil)
		    parsePids(response.body).each { |node, pid|
		      #saveAssertion "processInfo", "getNodePid: #{node}: #{host.name} - #{pid}"
		      nodeInfo = NodeInfo.new(node, host, pid)
		      getParam(nodeInfo, "-Xmx")		    
		      @nodeInfoMap[node] = nodeInfo
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
          str.split(',').each { |i|
            i.scan(/(.+)=(.+)/) { |match|
              pidmap[match[0]] = match[1]
            }
          }
          return pidmap
        end

        def getMemoryUsage
          @nodeInfoMap.values.each { |nodeInfo|
	    # use top if this value is incorrect, see printProcessInfo.rb in securityservices/test/bin
	    # Doing the rexec takes a long time, so we launch one thread per host
	    # to parallelize the actions.
	    Thread.fork() {
	      begin
		# -h   Do not display header
		# -p   Display info for specified PID
		# -o   output display
		command = "ps -h -p #{nodeInfo.pid} -o pcpu,pmem,sz,rss"
		#saveAssertion "processInfo", "#{nodeInfo.host.name} #{command}"
		response = @run.comms.new_message(nodeInfo.host).set_body("command[rexec]#{command}").request(30)
		parseMemoryUsage(nodeInfo, response.body)
		logNodeInfo(nodeInfo)
	      rescue => e
		saveAssertion "processInfo", "Unable to get process info: #{e.message}\n#{e.backtrace.join("\n")}"
	      end
	    }
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
	  nodeInfo.mem_size = b[2]
	  nodeInfo.rss = b[3]
        end
        
        def logNodeInfo(nodeInfo)
	  @nodeInfoFile << "#{nodeInfo.to_s}\n"
	  @nodeInfoFile.flush
        end
      end # LogNodeInfo
      
      # data object for NodeInfo
      class NodeInfo 
        
        attr_reader :name, :host, :pid
        attr_accessor :mem_size, :xmx, :pcpu, :pmem, :rss
        
        def initialize(name, host, pid, mem_size=nil, xmx=nil)
          @name = name
          @host = host
          @pid = pid
          @mem_size = mem_size
          @xmx = xmx
        end

        def NodeInfo.header_string
	  return "Date\tTime\tHost\tPID\tNode_Name\tSZ\tXMX\tPCPU\tPMEM\tRSS"
        end
       
        def to_s
	  now = Time.new
          "#{now.strftime("%m/%d/%Y")}\t#{now.strftime("%H:%M:%S")}\t#{@host.name}\t#{@pid}\t#{name}\t#{@mem_size}\t#{@xmx}\t#{pcpu}\t#{pmem}\t#{rss}"
        end
        
      end # end class NodeInfo
   end
end
