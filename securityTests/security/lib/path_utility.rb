#!/usr/bin/ruby

class PathUtility
  @@os=nil
  @@isWindows=false

  def PathUtility.isWindows
    PathUtility.init
    @@isWindows
  end

  def PathUtility.init
    if @@os == nil
      @@os=`uname`
      if @@os =~ /CYGWIN/
        @@isWindows=true
      end
    end
  end

  def PathUtility.fixPath(arg)
    PathUtility.init
    if @@isWindows
      arg = `cygpath -m -a #{arg}`.strip
      #puts "Converted: #{arg}"
    end
    arg
  end

  def PathUtility.getClassPath(classpath)
    PathUtility.init
    ret = ""
    if @@isWindows
      newcp = []
      classpath.each do |x|
        newcp << PathUtility.fixPath(x)
      end
      ret = newcp.join("\\;")
    else
      ret = classpath.join(":")
    end
    ret
  end
end
