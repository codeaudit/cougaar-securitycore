#! /usr/bin/ruby -W0

string=`top -b -n 1 | grep java | sort`
string.split("\n").each { |x|
  # This is a typical top output
  # Reformat process size for easy Excel display
  # PID   USER     PRI   NI SIZE RSS  SHARE STAT %CPU %MEM  TIME  COMMAND
  # 18359 asmt      17   0  163M 163M 33096 S     2.5  8.0   5:28 java

  topPattern1 = " *([0-9]*) *([a-zA-Z0-9_]*) *([0-9]*) *([0-9]*) *([0-9]*[KMG]?) *([0-9]*[KMG]?) *([0-9]*).*"
  topPattern2 = " *([a-zA-Z0-9_]*) *([0-9]*\.[0-9]*) *([0-9]*\.[0-9]*) *([0-9]*:[0-9]*) *([a-zA-Z0-9_]*).*"
  pid  =   x.gsub(/#{topPattern1}/, '\1').rjust(5)
  user  =  x.gsub(/#{topPattern1}/, '\2')
  pSizeString  = x.gsub(/#{topPattern1}/, '\5')
  lastItem = x.gsub(/#{topPattern1}/, '\6 \7')
  if x.index(lastItem) != nil
    x2 = x.slice(x.index(lastItem) + lastItem.size, x.size)
  else
    x2 = ""
  end
  stat   = x2.gsub(/#{topPattern2}/, '\1').ljust(4)
  cpu    = x2.gsub(/#{topPattern2}/, '\2').rjust(4)
  mem    = x2.gsub(/#{topPattern2}/, '\3').rjust(4)
  time   = x2.gsub(/#{topPattern2}/, '\4').rjust(5)
  command= x2.gsub(/#{topPattern2}/, '\5')

  pSizePattern = "([0-9]*)([KMG]?)"
  psize = pSizeString.gsub(/#{pSizePattern}/, '\1').to_i
  unit = pSizeString.gsub(/#{pSizePattern}/, '\2')
  if unit == 'M'
    psize = psize * 1024
  elsif unit == 'G'
    psize = psize * 1024 * 1024
  end
  psizeString = psize.to_s.rjust(10)
  psCommand = "ps -p #{pid} -o cmd --no-headers"
  cmd=`#{psCommand}`

  # The command-line looks like:
  #   java -Dorg.cougaar.node.name=1-1-CAVSQDN-NODE -Dorg.cougaar.core.agent.startTime
  if cmd.index("name") == nil
    nodeName = "__NO_NODE_INFO__"
  else
    nodeName = cmd.gsub(/.*name=(.*) -Dorg.*/, '\1')
  end
  
  if nodeName.strip.empty?
    nodeName = "__NO_NODE_INFO__"
  end
  nodeName = nodeName.ljust(27)

  #puts "node=#{nodeName}"
  hostName = `hostname`
  psTime = "#{Time.new.to_f}".ljust(16)

  s = "#{hostName} #{psTime} #{nodeName} #{pid} #{user} #{psizeString} #{stat} #{cpu} #{mem} #{time} #{command}".gsub(/\n/, '')
  puts s
}

