#!/usr/bin/ruby

class PathUtility
  @@os=nil
  @@isWindows=false

  def PathUtility.fixPath(arg)
    if @@os == nil
      @@os=`uname`
      if @@os =~ /CYGWIN/
        @@isWindows=true
      end
    end
    if @@isWindows
      arg = `cygpath -wl #{arg}`.strip
      #puts "Converted: #{arg}"
    end
    arg
  end
end
