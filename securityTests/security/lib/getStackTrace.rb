#!/usr/bin/ruby


class GetStackTrace < SecurityStressFramework

  def initialize(run)
    super(run)
    @interval=15
    @nodeInfoMap = {}
    @stackTraceId = 0
    @stackbasedir = "#{CIP}/workspace/test/stacktraces"
    Dir.mkdirs(@stackbasedir)
  end

  def getStressIds()
    return ['getStackTrace']
  end

  def getStack(nodename)
    stacktrace = nil
    begin
      logInfoMsg "getStack #{nodename}"
      nodeInfo = getJavaPid(nodename)
      logInfoMsg "getStack after getJavaPid #{nodename}"
      #stacktrace = getStackTraceFromProcFileSystem(nodeInfo.java_pid)
      logInfoMsg "Retrieving stack trace of #{nodename} at #{nodeInfo.node.host.name} - Java PID=#{nodeInfo.java_pid}"
      stacktrace = getStackTraceFromAcme(nodeInfo)
      logfile = "#{@stackbasedir}/stack-#{nodename}-#{nodeInfo.java_pid}.#{@stackTraceId}.log"
      f = File.new(logfile, "w");
      f << stacktrace
      f.close
      @stackTraceId += 1
    rescue => e
      logInfoMsg "Unable to collect stack trace: #{e} #{e.backtrace.join("\n")}"
    end
    return stacktrace
  end

  def getStackTraceFromAcme(nodeInfo)
    stacktrace = nil
    host = nodeInfo.node.host
    pid = nodeInfo.node_pid
    response = @run.comms.new_message(host).set_body("command[stdio]#{pid}").request(30)
    if response != nil
      puts "STDIO #{response.body}"
      if response.body =~ /Unregistered/
        # It was already registered, and we unregistered. Turn it back on
        response = @run.comms.new_message(host).set_body("command[stdio]#{pid}").request(30)
      end
    end
    response = @run.comms.new_message(host).set_body("command[stack]#{pid}").request(300)
    if response != nil
      stacktrace = response.body
    end
    return stacktrace
  end

  def getStackFromProcFileSystem(pid)
    begin
      script = "/tmp/cmd-stack-#{pid}-#{@stackTraceId}.sh"
      tmplogfile = "/tmp/stack-#{pid}.#{@stackTraceId}.log"
      f = File.new(script, "w");
      f << "#!/bin/sh\n"
      f << "cd /proc/#{pid}/fd\n"
      f << "cat 1 > #{tmplogfile} & \n"
      f << "kill -QUIT #{pid} \n"
      f << "sleep 30\n"
      f << "kill $!\n"
      f.chmod(0755)
      f.close
      # The script should be executed as root:
      out = `sh #{script}`
      f = File.open(tmplogfile, File::RDONLY)
      stacktrace = f.read
      f.close
      #sleep 1
      `rm #{script}`
      `rm #{tmplogfile}`
    rescue => e
      logInfoMsg "Unable to collect stack trace: #{e} #{e.backtrace.join("\n")}"
    end

    return stacktrace
  end

  def getJavaPid(nodename)
    host = nil
    nodeInfo = @nodeInfoMap[nodename]
    if (nodeInfo != nil && nodeInfo.java_pid != nil && nodeInfo.node_pid != nil)
      return nodeInfo
    end
    if (nodeInfo == nil)
      nodeInfo = NodeProcessInfo.new()
    end
    @run.society.each_node { |node|
      if node.name == nodename
        host = node.host
        nodeInfo.node = node
        break
      end
    }
    if (host != nil)
      response = @run.comms.new_message(host).set_body("command[list_java_pids]").request(60)
      if (response != nil)
        parsePids(response.body).each { |node, pid|
          if (node.name == nodename)
            nodeInfo.java_pid = pid
            break
          end
        }
      end
      response = @run.comms.new_message(host).set_body("command[list_xml_nodes]").request(60)
      if (response != nil)
        parsePids(response.body).each { |node, pid|
          if (node.name == nodename)
            nodeInfo.node_pid = pid
            break
          end
        }
      end
    end
    @nodeInfoMap[nodename] = nodeInfo
    logInfoMsg "#{nodeInfo.to_s}"
    return nodeInfo
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

  class NodeProcessInfo
    attr_accessor :node_pid, :java_pid, :node
    def to_s
      "Node PID:#{node_pid} - Java PID:#{java_pid} - Node: #{node.name}"
    end
  end
end

