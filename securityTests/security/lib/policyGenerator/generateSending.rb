
DATASET=ARGV[0]

sendMap = Hash.new

regexp = /MessageReaderAspect - Interception: message :(.*) : -> : (.*): type/

File.open(File.join(DATASET,"Sending.rb"), "w+") do |sending|
  sending.puts("$messages = []")
  Dir.glob(File.join(DATASET, "log4jlogs", "*.log")).each do |file|
    File.open(file) do |fd|
      fd.each_line do |logmsg|
        match = regexp.match(logmsg)
        if (match != nil) then
          sending.puts("$messages.push([\"#{match[1]}\", \"#{match[2]}\"])")
        end
      end
    end
  end
end
