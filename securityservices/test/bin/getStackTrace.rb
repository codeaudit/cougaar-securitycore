#!/usr/bin/ruby

interval=15

def getStack(pid, runcount)
   # As root:
   script = "/tmp/cmd-stack-#{pid}-#{runcount}.sh"
   f = File.new(script, "w");
   f << "#!/bin/sh\n"
   f << "cd /proc/#{pid}/fd\n"
   f << "cat 1 > /tmp/stack-#{pid}.#{runcount}.log & \n"
   f << "kill -QUIT #{pid} \n"
   f << "sleep 3\n"
   f << "kill $!\n"
   f.chmod(0755)
   f.close
   out = `sh #{script}`
   puts "/tmp/stack-#{pid}.#{runcount}.log : #{out}"
   #sleep 1
   `rm #{script}`
end

def javaProcess(runcount)
  pstreePattern = "\\(([0-9]*)\\)---java\\(([0-9]*)\\)"
  # Get the "Java" process PID
  javaPid = ""
  pstreeOut = `pstree -p | grep java | grep tcsh`
  #puts pstreeOut
  pstreeOut.scan(/#{pstreePattern}/) { |x|
    javaPid = x[1]
    #Thread.fork {
      getStack(javaPid, runcount)
    #}
  }

end

i = 1
`rm -f /tmp/stack-*`
`rm -f /tmp/cmd-stack-*`
while(true)
   javaProcess(i)
   i += 1
   #sleep(interval)
end

