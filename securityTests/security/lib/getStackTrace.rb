#!/usr/bin/ruby


class GetStackTrace < SecurityStressFramework

  def initialize(run)
    super(run)
    @interval=15
    @nodeInfoMap = {}
    @@stackTraceId = 0
    @stackbasedir = "#{CIP}/workspace/test/stacktraces"
    Dir.mkdirs(@stackbasedir)
  end

  def getStressIds()
    return ['getStackTrace']
  end

  def getStack(nodename)
    Thread.fork {
      stacktrace = nil
      begin
        @@stackTraceId += 1
        myStackTraceId = @@stackTraceId
        #logInfoMsg "getStack #{nodename}"
        nodeInfo = getJavaPid(nodename)
        #logInfoMsg "getStack after getJavaPid #{nodename}"
        #logInfoMsg "Retrieving stack trace of #{nodename} at #{nodeInfo.node.host.name} - Java PID=#{nodeInfo.java_pid} PID=#{nodeInfo.node_pid}"
        stacktrace = getStackTraceFromProcFileSystem(nodeInfo, myStackTraceId)
        #stacktrace = getStackTraceFromAcme(nodeInfo)
        logfile = "#{@stackbasedir}/stack-#{nodename}-#{nodeInfo.java_pid}.#{myStackTraceId}.log"
        f = File.new(logfile, "w");
        f << stacktrace
        f.close
      rescue => e
        logInfoMsg "Unable to collect stack trace: #{e} #{e.backtrace.join("\n")}"
      end
    }
  end

  def getStackTraceFromAcme(nodeInfo)
    stacktrace = nil
    host = nodeInfo.node.host
    pid = nodeInfo.node_pid
    response = @run.comms.new_message(host).set_body("command[stdio]#{pid}").request(30)
    if response != nil
      #puts "STDIO #{response.body}"
      if response.body =~ /Unregistered/
        # It was already registered, and we unregistered. Turn it back on
        response = @run.comms.new_message(host).set_body("command[stdio]#{pid}").request(30)
      end
    end
    #logInfoMsg "retrieving stack trace.."
    response = @run.comms.new_message(host).set_body("command[stack]#{pid}").request(60)
    if response != nil
      stacktrace = response.body
    else
      saveAssertion("wp_registration", "ACME did not return any stack trace")
    end
    return stacktrace
  end

  def getStackTraceFromProcFileSystem(nodeinfo, myStackTraceId)
    pid = nodeinfo.java_pid
    host = nodeinfo.node.host
    stacktrace = nil
    result = nil
    localhostname = `hostname`
    begin
      tmplogfile = "/tmp/stack-#{pid}.#{myStackTraceId}.log"

      # Build the script that will retrieve the stack trace
      script = "/tmp/cmd-stack-#{pid}-#{myStackTraceId}.sh"
      #logInfoMsg "Script: #{script} - #{tmplogfile}"
      f = File.new(script, "w");
      f << "#!/bin/sh\n"
      f << "cd /proc/$1/fd\n"
      f << "touch $2\n"
      f << "cat 1 > $2 & \n"
      f << "sleep 1\n"
      f << "kill -QUIT $1\n"
      f << "chmod 777 $2\n"
      f << "sleep 30\n"
      f << "kill $!\n"
      f.chmod(0755)
      f.close

      # Copy the script to the host where we want to do the stack trace
      if (localhostname != host.name)
        command = "scp -q #{script} #{host.name}:/tmp"
        result = system("#{command}")
        #logInfoMsg "Copying script to remote host: #{command} - #{result}"
        # And remove it from the operator host. It is no longer needed.
        result = File.delete(script)
      end
      # The script should be executed with root privileges
      command = "sudo sh #{script} #{pid} #{tmplogfile}"
      #logInfoMsg "Issuing command: #{command} at #{host.name}"
      #response = system("ssh #{host.name} #{command}")
      response = @run.comms.new_message(host).set_body("command[rexec]#{command}").request(300)
      # The stack should be in the tmplogfile at the remote host. Copy it to the operator host
      #logInfoMsg "Response : #{response}"
      if (localhostname != host.name)
        command = "scp -q #{host.name}:#{tmplogfile} /tmp"
        result = system("#{command}")
        #logInfoMsg "Copying stack trace file to operator host: #{command} - #{result}"
      end
      if (File.stat(tmplogfile).file?)
        f = File.open(tmplogfile, File::RDONLY)
        stacktrace = f.read
        f.close
        result = File.delete(tmplogfile)
      else
        # Somehow we could not get a stack trace.
      end
      # Remove the remote log file and remote script file
      if (localhostname != host.name)
        command = "sudo rm -f #{tmplogfile} #{script}"
        #logInfoMsg "Issuing command: #{command} at #{host.name}"
        response = @run.comms.new_message(host).set_body("command[rexec]#{command}").request(300)
      else
        command = "sudo rm -f #{script}"
        result = system("#{command}")
        #logInfoMsg "command: #{command} - #{result}"
      end
    rescue => e
      saveAssertion "wp_registration", "Unable to collect stack trace: #{e} #{e.backtrace.join("\n")}"
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
          if (node == nodename)
            nodeInfo.java_pid = pid
            break
          end
        }
      end
      response = @run.comms.new_message(host).set_body("command[list_xml_nodes]").request(60)
      if (response != nil)
        #logInfoMsg "Retrieving XML node pid: #{response}"
        parseNodePids(response.body).each { |node, pid|
          if (node == nodename)
            nodeInfo.node_pid = pid
            break
          end
        }
      end
    end
    @nodeInfoMap[nodename] = nodeInfo
    #logInfoMsg "#{nodeInfo.to_s}"
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

  # response should be in the format:
  # <message type="chat" to="acme_console@peach/expt-yew-ASMT-PING-1-1of1">
  #   <thread>JRT_47a4d76a4bb10bd85eff</thread>
  #  <body>Current Nodes:
  # PID: 20049 Node: MGMT-NODE Experiment: yew-ASMT-PING-1-1of1
  # PID: 19942 Node: CA-NODE Experiment: yew-ASMT-PING-1-1of1
  # PID: 19835 Node: ROOT-CA-NODE Experiment: yew-ASMT-PING-1-1of1
  # </body>
  # </message>
  def parseNodePids(str)
    pidmap = {}
    str.split(',').each { |i|
      i.scan(/PID: (.+) Node: (.+) Experiment: (.+)/) { |match|
        pidmap[match[1]] = match[0]
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

