
class DataProtection
  attr_accessor :summary

  def DataProtection.modifyPersistence(agent)
    puts "modifying #{agent}"

    cip = ENV['CIP']
    filePath = "#{cip}/workspace/P/#{agent}/delta_00000"
    puts "modifying #{filePath}"
    f = File.open(filePath, "r+")
    f.write("Testing signature verification")
    f.close    

  end

  def checkDataEncrypted(pattern, readSize=2000, showResults=true)
    failure = 0
    size = 0
    cip = ENV['CIP']
    @filelist = []
    run.society.each_node do |node|
      node.each_agent do |agent|
        cip = ENV['CIP']
        filePath = "#{cip}/workspace/P/#{agent.name}/delta_*"
        files = Dir[filePath]
#puts "#{agent.name}:  [#{files.to_s}]"
        files.each do |filename|
          begin
            f = File.open(filename, "r")
            data = f.read(readSize)
            size += 1
            if data.include? pattern
              @filelist << [agent.name, filename, false]
              failure += 1
              summary "#{filename} is not encrypted" if showResults
            else
              @filelist << [agent.name, filename, true]
            end
          rescue Exception => e
            logInfoMsg "Couldn't open #{filename}: #{e.message}"
          end
          f.close
        end
      end # agent
    end # node

    summary "There are #{failure} non-encrypted data files in #{size} persisted files" if showResults
    mopvalue = 0
    if size > 0
      mopvalue = (1 - Float(failure)/size) * 100.0
    else
      mopvalue = 100.0
    end
    @numFailures = failure
    result = (failure==0)
    @summary = "MOP2.2 (Protection of persisted data)", "There are #{100.0-mopvalue}% non-encrypted data files in #{size} persisted files"
    saveResult(result, @summary) if showResults
    
    return mopvalue
  end  

  def filelist
    return @filelist
  end

  def mopHtml
    info = []
    @filelist.each do |f|
      if f[2]
        info << "#{f[1]} passed"
      else
        info << "#{f[1]} failed"
      end
    end
    info << "passed #{@filelist.size-@numFailures} out of #{@filelist.size}"
    return info.join("<br/>\n")
  end
end
