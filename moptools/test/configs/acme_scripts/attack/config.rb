require 'security/attack/attackutil'

class ConfigFileStress < SecurityStressFramework
  def initialize(filename, attacknum, idmefnum, idmefEvent, idmefExpected)
    @filename = filename
    @attackNum = attacknum
    @text = "#{attacknum} stress text"
    @idmef = idmefnum
    @idmefExpected = idmefExpected
    @idmefEvent = idmefEvent
  end
  
  def preConditionalStartSociety
    agents = Util.findAgents("org.cougaar.core.security.test.ConfigReaderServlet")
    # just use the fist one on the list -- it doesn't matter which
    @agent = agents[0]
    @idmefWatcher = 
      Util::IdmefWatcher.new(@idmef, "Config file #{@filename} IDMEF event",
                             @idmefExpected, 
                             "IDMEF\\(#{@agent.name}\\)" + @idmefEvent);
    @idmefWatcher.start
  end

  def postConditionalNextOPlanStage
    url = Util.getRealUrl(@agent)
    result,url = Cougaar::Communications::HTTP.get("#{url}/readconfig?file=#{@filename}")
    logInfoMsg("Result from looking = #{result}")
    Util.saveResult(((result == @text) != @idmefExpected),
                    @attackNum,
                    "Config file #{@filename} test")
    sleep(1.minute)
    @idmefWatcher.stop
  end # postConditionalNextOPlanStage

  def postConditionalPlanningComplete
    @idmefWatcher.stop
  end

end # ConfigFileStress

class SignedConfigFile < ConfigFileStress
  def initialize(filename, attack, idmef, keystore, cert, idmefExpected)
    super(filename, attack, idmef, "Classification\\(org.cougaar.core.security.monitoring.JAR_VERIFICATION_FAILURE\\) AdditionalData\\([^)]#{$CIP}/configs/security/#{filename}.jar", idmefExpected)
    @keystore = keystore
    @cert = cert
    @password = 'keystore'
  end

  def preConditionalStartSociety
    super
    logInfoMsg "Creating configuration jar file #{$CIP}/configs/security/#{@filename}.jar"
    tmpfname = "/tmp/#{@filename}"
    file = Util.mkfile(tmpfname)
    file.print(@text)
    file.close();
    pwd = Dir.pwd
    Dir.chdir "/tmp"
    `jar cf #{$CIP}/configs/security/#{@filename}.jar #{@filename}`
    if (@keystore != nil)
      ret = `jarsigner -keystore #{$CIP}/configs/security/#{@keystore} -storepass #{@password} #{$CIP}/configs/security/#{@filename}.jar #{@cert}`
      logInfoMsg "Signed #{@filename}.jar with keystore #{$CIP}/configs/security/#{@keystore} #{@cert} #{ret}"
    end
    File.delete tmpfname
    Dir.chdir pwd
  end # preConditionalStartSociety

end # SignedConfigFile

class Security4a50Stress < SignedConfigFile
  def initialize
    super('4a50.txt', '4a50', '4a60', nil, nil, true)
  end
end # Security4a50Stress

class Security4a51Stress < SignedConfigFile
  def initialize
    super('4a51.txt', '4a51', '4a61', 'signingCA_keystore', 'expired', true)
  end
end # Security4a51Stress

class Security4a52Stress < SignedConfigFile
  def initialize
    super('4a52.txt', '4a52', '4a62', 'badsigningCA_keystore',
          'badsigner', true)
  end
end # Security4a52Stress

class Security4a53Stress < SignedConfigFile
  def initialize
    super('4a53.txt', '4a53', '4a63', 'signingCA_keystore',
          'privileged', true)
  end

  def rm(entry) 
    if File.stat(entry).directory?
      Dir.foreach(entry) { |file|
        if (file != "." && file != "..") 
          rm(File.join(entry,file))
        end
      }
      Dir.unlink(entry)
    else
      File.unlink(entry)
    end
  end

  def preConditionalStartSociety
    super
    pwd = Dir.pwd
    tmpdir = '/tmp/testjar'
    Dir.mkdir tmpdir
    Dir.chdir tmpdir
    fname = "#{$CIP}/configs/security/#{@filename}.jar"
    `unzip -q #{fname}`
    File.open(@filename, "w") { |file|
      file.print("Bad contents")
    }
    `zip -r #{fname}.jar *`
    Dir.chdir ".."
    rm(tmpdir)
    Dir.chdir pwd
  end
end # Security4a53Stress

class Security4a201Stress < SignedConfigFile
  def initialize
    super('4a201.txt', '4a201', '4a201', 'signingCA_keystore',
          'privileged', false)
  end
end # Security4a201Stress

