#! /usr/bin/ruby -W0

ACME_LOG_FILE = "/usr/local/acme/acme.log"

def getNodeName(pid)
  # Open acme.log file
  # Read from the end
  # Find PID in file - Should look like:
  #    [INFO] 2003-10-03 09:08:05 :: Plugin(acme_cougaar_xmlnode): DONE starting NODE: 19911
  # The PID in acme.log is not the Java PID. It is the "su" command:
  #    su -l -c java -Dorg.cougaar.node ...
  # The "su" command creates a "tcsh" process:
  #    -tcsh -c java -Dorg.cougaar.node ...
  # The "tcsh" process launches the "java" process that we are interested in:
  #    java -Dorg.cougaar.node.name ...
  # The pid argument is the pid of the java process
  #   - Lookup PPID of java process: pid1 of tcsh process
  #   - Lookup PPID of tcsh process: pid2 of su process, which is in the acme.log
  #   - Find pid2 in acme.log, starting from the end
  #   - Find node name in acme.log
  # [INFO] 2003-10-03 09:08:37 :: Plugin(acme_cougaar_xmlnode): Starting command:
  #    su -l -c 'java -Dorg.cougaar.node.name=1-AD-BDE-ROB-MGMT-NODE -Dor

  # pstree output looks like:
  #    pstree -p | grep java
  # init(1)-+-acme.sh(858)-+-ruby(888)---su(22228)---tcsh(22229)---java(22251)---java(22252)-+-java(22253)
  pstreePattern = "su\\(([0-9]*)\\)" 
  pstreeOut = `pstree -p | grep java | grep #{pid}`
  # Get the "su" process PID
  suPid = ""
  pstreeOut.scan(/#{pstreePattern}/) { |x|
    suPid = x[0]
  }
  #puts "suPid: #{suPid}"
  return getNodeNameFromPid(suPid.to_i)
end

def getNodeNameFromPid(pid)
  nodeName = "__NAME_NOT_FOUND__"
  $pidArray.reverse_each{ |x|
    #puts "#{x[0]} - #{x[1]}"
    if x[0] == pid
      nodeName = x[1]
      break
    end
  }
  #puts nodeName
  return nodeName
end

$pidArray = []
def readAcmeLogFile()
  acmeLogFile = File.new(ACME_LOG_FILE)
  javaPattern = "java -Dorg\.cougaar\.node\.name=([a-zA-Z\-_0-9]*) "
  pidPattern = "DONE starting NODE: ([0-9]*)"
  while (acmeLogFile.gets != nil) do
    $_.scan(/#{javaPattern}/) {|w|
      if acmeLogFile.gets != nil
        $_.scan(/#{pidPattern}/) { |x|
          #puts " #{w} - #{x}"
          binding = [x[0].to_i, w[0]]
          $pidArray.push(binding) 
        }
      end
    }
  end
  acmeLogFile.close
  #puts $pidArray
end

readAcmeLogFile()
#puts getNodeNameFromPid(12092)
#puts getNodeNameFromPid(25617)
#puts getNodeNameFromPid(234328)
#exit

string=`top -b -n 1 | grep java | sort`
string.split("\n").each { |x|
  # This is a typical top output
  # Reformat process size for easy Excel display
  # PID   USER     PRI   NI SIZE RSS  SHARE STAT %CPU %MEM  TIME  COMMAND
  # 18359 asmt      17   0  163M 163M 33096 S     2.5  8.0   5:28 java

  topPattern1 = " *([0-9]*) *([a-zA-Z0-9_]*) *([0-9]*) *([0-9]*) *([0-9]*\.?[0-9]*[KMG]?) *([0-9]*\.?[0-9]*[KMG]?) *([0-9]*).*"
  topPattern2 = " *([a-zA-Z0-9_]*) *([0-9]*\.?[0-9]*) *([0-9]*\.?[0-9]*) *([0-9]*:[0-9]*) *([a-zA-Z0-9_]*).*"
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

  pSizePattern = "([0-9]*\.?[0-9]*)"
  pSize = pSizeString.sub(/#{pSizePattern}/, '\1')
  unitI = pSizeString.index(/[KMG]/)
  unit =""
  if unitI != nil
    unit = pSizeString.slice(unitI, pSizeString.size)
  end
  pSizeF = pSize.to_f
  if unit == 'M'
    pSizeF = pSizeF * 1024
  elsif unit == 'G'
    pSizeF = pSizeF * 1024 * 1024
  end
  #puts "#{pSizeString} - #{pSizeF} - #{unit}"
  pSizeString = pSizeF.to_i.to_s.rjust(10)
  psCommand = "ps -p #{pid} -o cmd --no-headers"
  cmd=`#{psCommand}`

  # The command-line looks like:
  #   java -Dorg.cougaar.node.name=1-1-CAVSQDN-NODE -Dorg.cougaar.core.agent.startTime
  foundNodeName = true
  if cmd.index("name") == nil
    nodeName = "__NO_NODE_INFO__"
    foundNodeName = false
  else
    nodeName = cmd.gsub(/.*name=(.*) -Dorg.*/, '\1').strip
  end
  if nodeName.strip.empty?
    nodeName = "__NO_NODE_INFO__"
    foundNodeName = false
  end
  if foundNodeName == false
    # try with /usr/local/acme.log file
    nodeName = "#{getNodeName(pid.to_i)}*"
  end
  nodeName = nodeName.ljust(27)

  #puts "node=#{nodeName}"
  hostName = `hostname`
  psTime = "#{Time.new.to_f}".ljust(16)

  s = "#{hostName} #{psTime} #{nodeName} #{pid} #{user} #{pSizeString} #{stat} #{cpu} #{mem} #{time} #{command}".gsub(/\n/, '')
  puts s
}
