require 'framework/misc'
require 'framework/message_util'
require 'thread'

def createJar(contents_file, jar_file)
  `jar cf #{jar_file} #{contents_file}`
  jar_file
end

def signJar(jar_file, keystore, cert, password = 'keystore')
#  puts "jarsigner -keystore #{keystore} -storepass #{password} #{jar_file} #{cert}"
  `jarsigner -keystore #{keystore} -storepass #{password} #{jar_file} #{cert}`
  jar_file
end

@jar_lock = Mutex.new

def createJarConfig(configName, configContents = 'config file text')
  pwd = Dir.pwd
  Dir.chdir("#{$CIP}/configs/security")
  File.open(configName, "w") { |file|
    file.print(configContents)
  }
  jarName = "#{$CIP}/configs/security/#{configName}.jar"
  createJar(configName, jarName)
  Dir.chdir(pwd)
  jarName
end

def createComponentJar(componentName, componentContents = nil)
  if componentContents == nil
    componentContents = <<COMPONENT
package org.cougaar.core.security.test.temp;

public class #{componentName} extends org.cougaar.core.plugin.ComponentPlugin {
  public void execute() {}
  public void setupSubscriptions() {}
}
COMPONENT
  end
  javaFile = "/tmp/jar-#{componentName}/#{componentName}.java"
  dir = File.dirname(javaFile)
  Dir.mkdirs(dir)
  File.open(javaFile, "w") { |file|
    file.print(componentContents)
  }
  pwd = Dir.pwd
  jarDir = "/tmp/jar-#{componentName}"
  Dir.chdir(jarDir)
  classpath = getClasspath
  `javac -classpath #{classpath.join(':')} -d #{dir} #{javaFile}`
  jarFile = "#{$CIP}/lib/#{componentName}.jar"
  createJar("*", jarFile)
  Dir.chdir(pwd)
  File.rm_all(jarDir)
  return jarFile
end

def replaceFileInJar(jarFile, replacementFile)
  jarDir = "/tmp/jarDir-#{File.basename(jarFile)}"
  Dir.mkdirs(jarDir)
  pwd = Dir.pwd
  Dir.chdir(jarDir)
  files = `unzip -l #{jarFile}`.split
  baseFilename = File.basename(replacementFile)
  targetFile = nil
  files.each { |file|
    if (File.basename(file) == baseFilename)
      targetFile = file
      break
    end
  }
  if targetFile != nil
    `unzip -q #{jarFile} #{targetFile}`
  else
    targetFile = baseFilename
  end
  File.cp(replacementFile, targetFile)
  `zip -qr #{jarFile} *`
  Dir.chdir pwd
  File.rm_all(jarDir)
end
