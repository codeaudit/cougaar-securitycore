class Stress1d < SecurityStressFramework
  def initialize(run)
        @legitsuccesses = 0
        @malicioussuccesses=0
        @legittotal=0
        @malicioustotal=0
        @run = run
  end

  # StartSecurityBlackboardTesting
  def postPublishNextStage
    #Requires Oplan ready
    begin
      @run.society.each_agent(true) do |agent|
        url = "http://#{ agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testBlackboardManager?do=start&exp=#{@run.name}"
        #puts "starting testBlackboardManager #{url}"
        result = Cougaar::Communications::HTTP.get(url)
      end
    rescue
      raise_failure "Could not activate Testing", $!
    end
  end # postPublishNextStage

  # StopSecurityBlackboardTesting
  def preSocietyQuiesced
    begin
      @run.society.each_agent(true) do |agent|
        url ="http://#{agent.node.host.host_name}:#{agent.node.cougaar_port}/$#{agent.name}/testBlackboardManager?do=end&exp=#{@run.name}"
        #puts url
        req=Cougaar::Communications::HTTP.get(url)
      end #end each agent
      sleep 1.minutes
      #compile results
      mopValue = compileResults
      description="MOP 2.1 (Blackboard access control): #{mopValue} - Legitimate Successs=#{@legitsuccesses}, Malicious Successes=#{@malicioussuccesses} / Total tries=(Malicous)#{@malicioustotal}:(Legitimate)#{@legittotal}"
      if mopValue==100
          success = true
      else
          success = false
      end
      logInfoMsg description
      saveResult(success, '1d1',description)
      rescue
        raise_failure "Could not stop testing"
      end
  end # preSocietyQuiesced

  #Compile Results
  def compileResults
    mop = 0.0
    expname=@run.name
    resultsdirectory = "#{ENV['COUGAAR_INSTALL_PATH']}/workspace/security/blackboardresults"
    files = Dir["#{resultsdirectory}/*csv"]
    files.each{ |file|
      #puts "Filename:#{file}"
      lines= File.readlines(file)
      linenumber=1
      lines.each{ |line|
 	validexp = false
        if linenumber==2
          line.chomp!
          #puts line
          results = line.split(',')
          colnumber=1
          successes = 0
          total = 0
          results.each{ |result|
            #puts result
            if colnumber==1
              if result.to_s =~/#{expname}/
                validexp = true
              end
            end
            if validexp==true
              if colnumber==4
                successes = result.to_i
              end
              if colnumber==6
                total =  result.to_i
              end
              if colnumber==8
                if result.to_s =~/LEGIT/i
                  @legitsuccesses = @legitsuccesses + successes
                  @legittotal = @legittotal + total
                end
                if result.to_s =~/MAL/i
                  @malicioussuccesses = @malicioussuccesses + successes
                  @malicioustotal = @malicioustotal + total
                end
              end
            end #end valid exp
            colnumber = colnumber+1
          }#end looping through csv columns
        end #end parsing line 2 of csv
        linenumber = linenumber+1
      }#end looping through file lines
    }#end lopping through files
    totalruns = @legittotal + @malicioustotal
    totalsuccesses = @legitsuccesses + @malicioussuccesses
    mop = 100 * (totalsuccesses.to_f / totalruns.to_f)
    return mop
  end #compile results

end # Stress1d

