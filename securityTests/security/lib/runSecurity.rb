#!/usr/bin/env ruby

=begin
This file sets the load path (from globals.rb), presents a menu of runnable
scripts, and runs the selected script.  The script may be automatically
run by passing in the name (without the extension), for example,
    ./runSecurity 1a
will run the security/1a.rb script after a little set up.
=end

def runSecurity(scriptName)
   requireScript(scriptName)
   experimentClass = getExperimentClass(scriptName)
   experimentClass.new.runExperiment
end

def requireScript(scriptName)
   script = $ScriptsDir + $DirSeparator + scriptName
   begin
      require(script)
   rescue Exception => e
     puts "Received an error while trying to require '#{script}'."
     puts "#{e.class}: #{e.message}"
     puts e.backtrace.join("\n")
     exit 1 unless $Debugging
   end
end

$ExperimentClassNameExceptions = {'example'=>'ExampleEnvironment'}

def getExperimentClass(scriptName)
   if $ExperimentClassNameExceptions.has_key?(scriptName) then
      name = $ExperimentClassNameExceptions[scriptName]
   else
      name = 'Security'+scriptName+'Experiment'
   end

   begin
      return eval(name)
   rescue Exception => e
     puts "In trying to get the class for script '#{scriptName}', couldn't find the class '#{name}'.  There could be a miss-spelling or you may need to add it to the envClassExceptions."
     puts "#{e.class}: #{e.message}"
     puts e.backtrace.join("\n")
     exit 1 unless $Debugging
   end
end


def getScriptName(dir=$ScriptsDir)
   if ARGV.size == 0 then
      selectFromMenu(dir)
   else
      ARGV[0]
   end
end



def selectFromMenu(dir)
   files = getFileList(dir)
   files.size.times do |n|
      print "#{n+1}. #{files[n]}\n"
   end
   puts "99. quit"
   puts
   print "Enter a number: "
   gets
   n = eval($_)
   if 1<=n and n<=files.size then
      return files[n-1]
   elsif n==99 then
      return nil
   else
      return selectFromMenu(dir)
   end
end

def getFileList(dir, ext="*.rb")
   files = `ls #{dir}/#{ext}`.split
   files = files.collect do |f|
      file = f.split($DirSeparator)[-1]
      m = /(.*)\.rb/.match(file)
      m[1]
   end
end


