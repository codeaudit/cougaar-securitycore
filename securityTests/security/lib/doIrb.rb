Thread.abort_on_exception = true

class Object
 def doIrb(prompt='ruby', initialPrompt="Type 'quit' to end")
   # modified from a JRuby example
   line = ''
   indent=0
   $stdout.sync = TRUE
   puts
   puts initialPrompt
   print "#{prompt}> "
   while TRUE
     l = STDIN.gets
     unless l
       break if line == ''
     else
       line = line + l 
       if l =~ /,\s*$/
         print "#{prompt}| "
         next
       end
       if l =~ /^\s*(class|module|def|if|unless|case|while|until|for|begin)\b[^_]/ or l=~/.* do *\|/
         indent += 1
       end
       if l =~ /^\s*end\b[^_]/
         indent -= 1
       end
       if l =~ /\{\s*(\|.*\|)?\s*$/
         indent += 1
       end
       if l =~ /^\s*\}/
         indent -= 1
       end
       if indent > 0
         print "#{prompt}| "
         indent.times {|x| print '  '}
         next
       else
         break if l =~ /^\s*quit\s*$/
       end
     end
     begin
       result = self.instance_eval(line).to_s, "\n"
       result = result[0,300] if result.size > 300
       print result
       #print self.instance_eval(line).inspect, "\n"
     rescue ScriptError, StandardError => e
#       $! = 'exception raised' unless $!
#       print "ERR: ", $!, "\n"
       puts "error: #{e.class}: #{e.message}"
       puts e.backtrace.join("\n")
     rescue SystemExit => e
       exit
     rescue Exception => e
       puts "error: #{e.class}: #{e.message}"
       puts e.backtrace.join("\n")
     end
     break unless l 
     line = ''
     print "#{prompt}> "
   end
   print "\n"
 end
end


