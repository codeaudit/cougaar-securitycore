#! /usr/bin/ruby -W0

string=`top -b -n 1 | grep java | sort`
string.split("\n").each { |x|
  pid = x.gsub(/ *([0-9]*).*/, '\1')
  #puts "pid=#{pid}"
  cmd=`ps -p #{pid} -o cmd --no-headers`
  # The command-line looks like:
  #   java -Dorg.cougaar.node.name=1-1-CAVSQDN-NODE -Dorg.cougaar.core.agent.startTime
  nodeName = cmd.gsub(/.*name=(.*) -Dorg.*/, '\1')
  if nodeName.strip.empty?
    nodeName = cmd
  end
  if nodeName.strip.empty?
    nodeName = "__NO_NODE_INFO__"
  end
  nodeName = nodeName.ljust(27)
  hostName = `hostname`
  time = "#{Time.new.to_f}".ljust(16)
  s = "#{hostName} #{time} #{nodeName} #{x}".gsub(/\n/, '')
  puts s
}

