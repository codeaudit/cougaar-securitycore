#!/usr/bin/ruby

interval=10

def getStack(pid, runcount)
   # As root:
   f = File.new("/tmp/cmd-stack.sh", "w");
   f << "#!/bin/sh\n"
   f << "cd /proc/#{pid}/fd\n"
   f << "cat 1 > /tmp/stack-#{pid}.#{runcount}.log & \n"
   f << "kill -QUIT #{pid} \n"
   f << "sleep 1\n"
   f << "kill $!\n"
   f.chmod(0755)
   f.close
   out = `sh /tmp/cmd-stack.sh`
   puts "/tmp/stack-#{pid}.#{runcount}.log"
   sleep 1
   #`rm /tmp/cmd-stack.sh`
end

def javaProcess(runcount)
  pstreePattern = "\\(([0-9]*)\\)---java\\(([0-9]*)\\)"
  # Get the "Java" process PID
  javaPid = ""
  pstreeOut = `pstree -p | grep java | grep tcsh`
  #puts pstreeOut
  pstreeOut.scan(/#{pstreePattern}/) { |x|
    javaPid = x[1]
    getStack(javaPid, runcount)
  }

end

i = 1
while(true)
   javaProcess(i)
   i += 1
   sleep(interval)
end

