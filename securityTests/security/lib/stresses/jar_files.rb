require 'security/lib/misc'
require 'security/lib/jar_util'
require 'security/lib/message_util'
require 'thread'

class StressIdmefJar < SecurityStressFramework

  def initialize(idmefNum, idmefName, idmefEvent)
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
    sleep 2.minutes # wait for url to be poked
    @idmefWatcher.stop
  end # postConditionalNextOPlanStage
end # IdmefJarStress

class StressJarFile < SecurityStressFramework
  KEYSTORE_FILE   = "#{$CIP}/configs/security/bootstrap_keystore"
  KEYSTORE_BACKUP = KEYSTORE_FILE + ".orig"
  KEYSTORE_TEST   = "#{$CIP}/configs/testKeystore/test_bootstrap_keystore"
  GOOD_KEYSTORE   = "#{$CIP}/operator/signingCA_keystore"
  TEST_KEYSTORE   = "#{$CIP}/configs/testKeystore/testSigningCA_keystore"

  def initialize(componentName, attackNum, attackName, successExpected)
    @testAgent = nil
    @attackNum = attackNum
    @attackName = attackName
    @componentName = componentName
    @successExpected = successExpected
  end

  def postLoadSociety
    # move the bootstrap keystore to a backup and copy the test keystore in
    begin
      File.stat(KEYSTORE_BACKUP)
    rescue
      File.stat(KEYSTORE_TEST)
      File.rename(KEYSTORE_FILE, KEYSTORE_BACKUP)
      File.cp(KEYSTORE_TEST, KEYSTORE_FILE)
    end
  end

  def postStopSociety
    # restore the original keystore
    begin
      File.stat(KEYSTORE_BACKUP)
      File.rename(KEYSTORE_BACKUP, KEYSTORE_FILE)
    rescue
    end
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
  def initialize(attackNum, attackName, successExpected,
                 keystore = nil, cert = nil)
    super("org.cougaar.core.security.test.ConfigReaderServlet",
          attackNum, attackName, successExpected)
    @filename = "#{attackNum}.txt"
    @jarFile = createJarConfig(@filename, attackName)
    if (keystore != nil)
      signJar(@jarFile, keystore, cert)
    end
  end

  def postLoadSociety
    super
    installConfigReaderServlet()
  end

  def postStopSociety
    super
    File.unlink(@jarFile)
  end

  def pokeUrl
    url = "#{@testAgent.uri}/readconfig?file=#{@attackNum}.txt"
    result, url = Cougaar::Communications::HTTP.get(url)
#    logInfoMsg("Result from looking = #{result}")
    return result == @attackName
  end
end # StressConfigJar

class StressConfigIdmef < StressIdmefJar
  def initialize(idmefNum, idmefName, jarFile)
    super(idmefNum, idmefName,
          "IDMEF\\([^)]+\\) Classification\\(org.cougaar.core.security.monitoring.JAR_VERIFICATION_FAILURE\\) AdditionalData\\([^)]*#{jarFile}")
  end
end # StressConfigIdmef

class Stress4a50 < StressConfigJar
  def initialize
    super("4a50", "Load a configuration stored in an unsigned jar file", false)
  end
end # Stress4a50

class Stress4a51 < StressConfigJar
  def initialize
    super("4a51",
          "Load a configuration stored in a jar signed by expired cert", false,
          TEST_KEYSTORE, "expired")
  end
end # Stress4a51

class Stress4a52 < StressConfigJar
  def initialize
    super("4a52",
          "Load a configuration stored in a jar signed by untrusted cert",
          false, TEST_KEYSTORE, "badsigner")
  end
end # Stress4a52

class Stress4a53 < StressConfigJar
  def initialize
    super("4a53",
          "Load a configuration stored in a tampered, but properly signed jar",
          false, GOOD_KEYSTORE, "privileged")
  end

  def preConditionalStartSociety
    super
    filename = "#{$CIP}/configs/security/#{@filename}"
    File.open(filename, "w") { |file|
      file.print("Bad contents")
    }
    replaceFileInJar(@jarFile, filename, true)
  end
end # Stress4a53


class Stress4a201 < StressConfigJar
  def initialize
    super("4a201",
          "Load a configuration stored in a jar signed by correct cert",
          true, GOOD_KEYSTORE, "privileged")
  end
end # Stress4a201

class Stress4a60 < StressConfigIdmef
  def initialize
    super("4a60", "IDMEF event after 4a50", "4a50.txt.jar")
  end
end # Stress4a60

class Stress4a61 < StressConfigIdmef
  def initialize
    super("4a61", "IDMEF event after 4a51", "4a51.txt.jar")
  end
end # Stress4a61

class Stress4a62 < StressConfigIdmef
  def initialize
    super("4a62", "IDMEF event after 4a52", "4a52.txt.jar")
  end
end # Stress4a62

class Stress4a63 < StressConfigIdmef
  def initialize
    super("4a63", "IDMEF event after 4a53", "4a53.txt.jar")
  end
end # Stress4a63

class StressComponentJar < StressJarFile
  def initialize(attackNum, attackName, successExpected,
                 keystore = nil, cert = nil)
    super("org.cougaar.core.security.test.RunCodeServlet",
          attackNum, attackName, successExpected)
    @component = "Stress#{attackNum}"
    @jarFile = createComponentJar(@component, <<COMPONENT)
    package org.cougaar.core.security.test.temp#{@component};
public class #{@component} implements Runnable {
  public void run() {}
}
COMPONENT
    if (keystore != nil)
      signJar(@jarFile, keystore, cert)
    end
  end

  def postLoadSociety
    super
    installCodeRunnerServlet()
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
  def initialize
    super("5a1", "Load code from unsigned jar file", false)
  end
end

class Stress5a2 < StressComponentJar
  def initialize
    super("5a2", "Load code from jar signed by expired cert", false,
          TEST_KEYSTORE, "expired")
  end
end

class Stress5a3 < StressComponentJar
  def initialize
    super("5a3", "Load code from jar signed by not trusted cert", false,
          TEST_KEYSTORE, "badsigner")
  end
end

class Stress5a4 < StressComponentJar
  def initialize
    super("5a4", "Load code from a tampered signed jar", false,
          GOOD_KEYSTORE, "privileged")
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
  def initialize
    super("5a101", "Load code from a signed jar", true,
          GOOD_KEYSTORE, "privileged")
  end
end

class StressComponentIdmef < StressIdmefJar
  def initialize(idmefNum, idmefName, exceptionText)
    super(idmefNum, idmefName,
          "IDMEF\\([^)]+\\) Classification\\(org.cougaar.core.security.monitoring.JAR_VERIFICATION_FAILURE\\) AdditionalData\\([^)]*#{exceptionText}")
  end
end

class Stress5a20 < StressComponentIdmef
  def initialize
    super("5a20", "IDMEF generated during 5a1", "Stress5a1.jar")
  end
end

class Stress5a21 < StressComponentIdmef
  def initialize
    super("5a21", "IDMEF generated during 5a2", "Stress5a2.jar")
  end
end

class Stress5a22 < StressComponentIdmef
  def initialize
    super("5a22", "IDMEF generated during 5a3", "Stress5a3.jar")
  end
end

class Stress5a23 < StressComponentIdmef
  def initialize
    super("5a23", "IDMEF generated during 5a4", "Stress5a4.class")
  end
end
