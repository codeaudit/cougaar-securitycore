require 'security/lib/misc'
require 'security/lib/jar_util'
require 'security/lib/message_util'
require 'thread'
require 'ftools'

class StressIdmefJar < SecurityStressFramework

  def initialize(run, idmefNum, idmefName, idmefEvent)
    super(run)
    @idmefNum = idmefNum
    @idmefName = idmefName
    @idmefEvent = idmefEvent

  end
  
  def preConditionalStartSociety
    @idmefWatcher = IdmefWatcher.new(@idmefNum, @idmefName, true, 
                                     @idmefEvent);
    @idmefWatcher.start
  end
  
  def postConditionalNextOPlanStage
    Thread.fork {
      sleep 2.minutes # wait for url to be poked
      @idmefWatcher.stop
    }
  end # postConditionalNextOPlanStage
end # IdmefJarStress

$installedTestKeystore = false

class CleanupJarFiles < SecurityStressFramework
  KEYSTORE_FILE   = "#{CIP}/configs/security/bootstrap_keystore"
  KEYSTORE_BACKUP = KEYSTORE_FILE + ".orig"
  KEYSTORE_TEST   = "#{CIP}/configs/testKeystore/test_bootstrap_keystore"
  GOOD_KEYSTORE   = "#{CIP}/operator/signingCA_keystore"
  TEST_KEYSTORE   = "#{CIP}/configs/testKeystore/testSigningCA_keystore"

  def initialize(run)
    super(run)
  end

  def cleanupJarFiles
    # restore the original keystore
    begin
      File.stat(KEYSTORE_BACKUP)
      File.rename(KEYSTORE_BACKUP, KEYSTORE_FILE)
    rescue => ex
      logInfoMsg "Did not restore backup keystore: #{ex}"
    end
    begin
      basedir = "#{CIP}/configs/security"
      Dir.foreach(basedir) do |f|
	if f =~ /^Stress4a/
	  File.delete("#{basedir}/#{f}")
	end
      end
    rescue => ex2
      logInfoMsg "No jar file to cleanup #{ex2}"
    end
  end
end

class StressJarFile < SecurityStressFramework
  KEYSTORE_FILE   = "#{CIP}/configs/security/bootstrap_keystore"
  KEYSTORE_BACKUP = KEYSTORE_FILE + ".orig"
  KEYSTORE_TEST   = "#{CIP}/configs/testKeystore/test_bootstrap_keystore"
  GOOD_KEYSTORE   = "#{CIP}/operator/signingCA_keystore"
  TEST_KEYSTORE   = "#{CIP}/configs/testKeystore/testSigningCA_keystore"

  def initialize(run, componentName, attackNum, attackName, successExpected)
    super(run)
    @testAgent = nil
    @attackNum = attackNum
    @attackName = attackName
    @componentName = componentName
    @successExpected = successExpected
    @cleanupJar = CleanupJarFiles.new(run)
  end

  def postLoadSociety
    # move the bootstrap keystore to a backup and copy the test keystore in
    if !$installedTestKeystore
      begin
	File.stat(KEYSTORE_BACKUP)
      rescue
	# We don't have a backup of the original keystore file
	# Do the backup
	logInfoMsg "Backing up bootstrap_keystore file..."
	File.rename(KEYSTORE_FILE, KEYSTORE_BACKUP)
      end
      begin
	File.stat(KEYSTORE_TEST)
	File.copy(KEYSTORE_TEST, KEYSTORE_FILE)
      rescue => ex2
	logInfoMsg "Unable to copy test keystore file: #{ex2}"
      end
      $installedTestKeystore = true
    end
  end

  def postStopSociety
    @cleanupJar.cleanupJarFiles()
  end

  def preConditionalStartSociety
    run.society.each_agent_with_component(@componentName) { |agent|
      @testAgent = agent
      break
    }
  end

  def postConditionalNextOPlanStage
    result = pokeUrl
    saveResult(result == @successExpected, @attackNum, @attackName)
  end # postConditionalNextOPlanStage

  def pokeUrl
    raise "You shouldn't be calling this method!"
  end
end # StressJarFile

class StressConfigJar < StressJarFile
  def initialize(run, attackNum, attackName, successExpected,
                 keystore = nil, cert = nil)
    super(run, "org.cougaar.core.security.test.ConfigReaderServlet",
          attackNum, attackName, successExpected)
    @keystore = keystore
    @cert = cert
  end

  def postLoadSociety
    @filename = "#{@attackNum}.txt"
    s = "Creating"
    if keystore != nil
      s = s + " and signing"
    end
    s = s + " config jar file containing #{@filename}"
    saveUnitTestResult(@attackName, s)
    @jarFile = createJarConfig(@filename, @attackName)
    if (@keystore != nil)
      signJar(@jarFile, @keystore, @cert)
    end

    super
    #installConfigReaderServlet()
  end

  def postStopSociety
    super
    File.unlink(@jarFile)
  end

  def pokeUrl
    url = "#{@testAgent.uri}/readconfig?file=#{@attackNum}.txt"
    result, url = Cougaar::Communications::HTTP.get(url)
    saveUnitTestResult(@attackName, "Result from looking #{url}: #{result}")
#    logInfoMsg("Result from looking = #{result}")
    return result == @attackName
  end
end # StressConfigJar

class StressConfigIdmef < StressIdmefJar
  def initialize(run, idmefNum, idmefName, jarFile)
    super(run, idmefNum, idmefName,
          "IDMEF\\([^)]+\\) Classification\\(org.cougaar.core.security.monitoring.JAR_VERIFICATION_FAILURE\\) AdditionalData\\([^)]*#{jarFile}")
  end
end # StressConfigIdmef

class Stress4a50 < StressConfigJar
  def initialize(run)
    super(run, "Stress4a50", "Load a configuration stored in an unsigned jar file", false)
  end
  def getStressIds()
    return ["Stress4a50"]
  end
end # Stress4a50

class Stress4a51 < StressConfigJar
  def initialize(run)
    super(run, "Stress4a51",
          "Load a configuration stored in a jar signed by expired cert", false,
          TEST_KEYSTORE, "expired")
  end
  def getStressIds()
    return ["Stress4a51"]
  end
end # Stress4a51

class Stress4a52 < StressConfigJar
  def initialize(run)
    super(run, "Stress4a52",
          "Load a configuration stored in a jar signed by untrusted cert",
          false, TEST_KEYSTORE, "badsigner")
  end
  def getStressIds()
    return ["Stress4a52"]
  end
end # Stress4a52

class Stress4a53 < StressConfigJar
  def initialize(run)
    super(run, "Stress4a53",
          "Load a configuration stored in a tampered, but properly signed jar",
          false, GOOD_KEYSTORE, "privileged")
  end
  def getStressIds()
    return ["Stress4a53"]
  end

  def preConditionalStartSociety
    super
    filename = "#{CIP}/configs/security/#{@filename}"
    saveUnitTestResult("Stress4a53", "Adding #{filename} to #{@jarFile}...")
    File.open(filename, "w") { |file|
      file.print("Bad contents")
    }
    replaceFileInJar(@jarFile, filename, true)
  end
end # Stress4a53


class Stress4a201 < StressConfigJar
  def initialize(run)
    super(run, "Stress4a201",
          "Load a configuration stored in a jar signed by correct cert",
          true, GOOD_KEYSTORE, "privileged")
  end
  def getStressIds()
    return ["Stress4a201"]
  end
end # Stress4a201

class Stress4a60 < StressConfigIdmef
  def initialize(run)
    super(run, "Stress4a60", "IDMEF event after 4a50", "Stress4a50.txt.jar")
  end
  def getStressIds()
    return ["Stress4a60"]
  end
end # Stress4a60

class Stress4a61 < StressConfigIdmef
  def initialize(run)
    super(run, "Stress4a61", "IDMEF event after 4a51", "Stress4a51.txt.jar")
  end
  def getStressIds()
    return ["Stress4a61"]
  end
end # Stress4a61

class Stress4a62 < StressConfigIdmef
  def initialize(run)
    super(run, "Stress4a62", "IDMEF event after 4a52", "Stress4a52.txt.jar")
  end
  def getStressIds()
    return ["Stress4a62"]
  end
end # Stress4a62

class Stress4a63 < StressConfigIdmef
  def initialize(run)
    super(run, "Stress4a63", "IDMEF event after 4a53", "Stress4a53.txt.jar")
  end
  def getStressIds()
    return ["Stress4a63"]
  end
end # Stress4a63

class StressComponentJar < StressJarFile
  def initialize(run, attackNum, attackName, successExpected,
                 keystore = nil, cert = nil)
    super(run, "org.cougaar.core.security.test.RunCodeServlet",
          attackNum, attackName, successExpected)
    @keystore = keystore
    @cert = cert
  end

  def postLoadSociety
    @component = "Stress#{@attackNum}"
    @jarFile = createComponentJar(@component, <<COMPONENT)
    package org.cougaar.core.security.test.temp#{@component};
public class #{@component} implements Runnable {
  public void run() {}
}
COMPONENT
    if (@keystore != nil)
      signJar(@jarFile, @keystore, @cert)
    end
    super
    #installCodeRunnerServlet()
  end

  def postStopSociety
    super
    File.unlink(@jarFile)
  end

  def pokeUrl
    url = "#{@testAgent.uri}/runCode?class=org.cougaar.core.security.test.temp#{@component}.#{@component}"
#    puts("looking in url #{url}")
    result, url = Cougaar::Communications::HTTP.get(url)
#    puts("successful #{@component}: #{(result =~ /Success/) != nil}, url = #{url}")
#    puts("found result: #{result}")
    return ((result =~ /Success/) != nil)
  end
end # StressComponentJar

class Stress5a1 < StressComponentJar
  def initialize(run)
    super(run, "Stress5a1", "Load code from unsigned jar file", false)
  end
  def getStressIds()
    return ["Stress5a1"]
  end
end

class Stress5a2 < StressComponentJar
  def initialize(run)
    super(run, "Stress5a2", "Load code from jar signed by expired cert", false,
          TEST_KEYSTORE, "expired")
  end
  def getStressIds()
    return ["Stress5a2"]
  end
end

class Stress5a3 < StressComponentJar
  def initialize(run)
    super(run, "Stress5a3", "Load code from jar signed by not trusted cert", false,
          TEST_KEYSTORE, "badsigner")
  end
  def getStressIds()
    return ["Stress5a3"]
  end
end

class Stress5a4 < StressComponentJar
  def initialize(run)
    super(run, "Stress5a4", "Load code from a tampered signed jar", false,
          GOOD_KEYSTORE, "privileged")
  end
  def getStressIds()
    return ["Stress5a4"]
  end

  def preConditionalStartSociety
    super
    File.rename(@jarFile, "#{@jarFile}.bk")
    createComponentJar(@component, <<COMPONENT)
package org.cougaar.core.security.test.temp#{@component};
public class #{@component} implements Runnable {
  int _tempVar = 0;
  public void run() {}
}
COMPONENT
    jarDir = "/tmp/jar-#{@component}-new"
    Dir.mkdirs(jarDir)
#    puts "======================================================"
    foo = `cd #{jarDir} && jar xf #{@jarFile} org/cougaar/core/security/test/temp#{@component}/#{@component}.class META-INF/MANIFEST.MF`
#    puts foo
    foo = `jar umf #{jarDir}/META-INF/MANIFEST.MF #{@jarFile}.bk -C #{jarDir} org/cougaar/core/security/test/temp#{@component}/#{@component}.class`
#    puts foo
#    puts "======================================================"
    File.rename("#{@jarFile}.bk", @jarFile)
    File.rm_all(jarDir)
  end
end

class Stress5a101 < StressComponentJar
  def initialize(run)
    super(run, "Stress5a101", "Load code from a signed jar", true,
          GOOD_KEYSTORE, "privileged")
  end
  def getStressIds()
    return ["Stress5a101"]
  end
end

class StressComponentIdmef < StressIdmefJar
  def initialize(run, idmefNum, idmefName, exceptionText)
    super(run, idmefNum, idmefName,
          "IDMEF\\([^)]+\\) Classification\\(org.cougaar.core.security.monitoring.JAR_VERIFICATION_FAILURE\\) AdditionalData\\([^)]*#{exceptionText}")
  end
end

class Stress5a20 < StressComponentIdmef
  def initialize(run)
    super(run, "Stress5a20", "IDMEF generated during 5a1", "Stress5a1.jar")
  end
  def getStressIds()
    return ["Stress5a20"]
  end
end

class Stress5a21 < StressComponentIdmef
  def initialize(run)
    super(run, "Stress5a21", "IDMEF generated during 5a2", "Stress5a2.jar")
  end
  def getStressIds()
    return ["Stress5a21"]
  end
end

class Stress5a22 < StressComponentIdmef
  def initialize(run)
    super(run, "Stress5a22", "IDMEF generated during 5a3", "Stress5a3.jar")
  end
  def getStressIds()
    return ["Stress5a22"]
  end
end

class Stress5a23 < StressComponentIdmef
  def initialize(run)
    super(run, "Stress5a23", "IDMEF generated during 5a4", "Stress5a4.class")
  end
  def getStressIds()
    return ["Stress5a23"]
  end
end
