require 'thread'

if ! defined? CIP
  CIP = ENV['CIP']
end

if (defined? File.rm_all) == nil
  # copied from misc so it isn't required in security services
  class File
    def self.rm_all(entry)
      stat = nil
      begin
        stat = File.stat(entry)
      rescue
        return nil
      end
      if stat.directory?
        Dir.foreach(entry) { |file|
          if (file != "." && file != "..")
            rm_all(File.join(entry,file))
          end
        }
        Dir.unlink(entry)
      else
        File.unlink(entry)
      end
    end

    def self.cp(fromFile, toFile)
      begin
        if File.stat(toFile).directory?
          to = File.join(toFile, File.basename(fromFile))
        end
      rescue
        # don't worry about it if the file doesn't exist
      end
      File.open(fromFile, "r") { |from|
        File.open(toFile, "w") { |to|
          while (!from.eof?)
            buf = from.read(1000)
            if (buf != nil)
              to.write(buf)
            end
          end
        }
      }
    end # cp
  end # File

  class Dir
    def self.mkdirs(dir)
      head, tail = File.split(dir)
      if (head != dir)
        mkdirs(head)
      end

      begin
        stat = File.stat(dir)
      rescue
        Dir.mkdir(dir)
      end
    end # mkdirs
  end # Dir
end

def createJar(contents_file, jar_file, jar_dir = nil)
  if jar_dir != nil
    arg = "-C #{jar_dir}"
  else
    arg = ""
  end
  `jar cf #{jar_file} #{arg} #{contents_file}`
  jar_file
end

def signJar(jar_file, keystore, cert, password = 'keystore')
#  puts "jarsigner -keystore #{keystore} -storepass #{password} #{jar_file} #{cert}"
  `cd #{File.dirname(jar_file)} && jarsigner -keystore #{keystore} -storepass #{password} #{jar_file} #{cert}`
  jar_file
end

@jar_lock = Mutex.new

def createJarConfig(configName, configContents = 'config file text')
  File.open("#{CIP}/configs/security/#{configName}", "w") { |file|
    file.print(configContents)
  }
  jarName = "#{CIP}/configs/security/#{configName}.jar"
  createJar(configName, jarName, "#{CIP}/configs/security")
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
  classpath = getClasspath
  `javac -classpath #{classpath.join(':')} -d #{dir} #{javaFile}`
  jarFile = "#{CIP}/lib/#{componentName}.jar"
  createJar(".", jarFile, dir)
  File.rm_all(dir)
  return jarFile
end

def replaceFileInJar(jarFile, replacementFile, keepManifest = false)
#  puts "replacing #{replacementFile} in #{jarFile}"
  jarDir = "/tmp/jarDir-#{File.basename(jarFile)}"
  Dir.mkdirs(jarDir)
  files = `jar tf #{jarFile}`.split
  baseFilename = File.basename(replacementFile)
  targetFile = nil
  files.each { |file|
    if (File.basename(file) == baseFilename)
      targetFile = file
      break
    end
  }
#  puts "========================"
  if targetFile != nil
#    puts "found file: #{targetFile}"
    `cd #{jarDir} && jar xf #{jarFile} #{targetFile} 2&>1`
  else
#    puts "the file wasn't found, so using #{baseFilename}"
    targetFile = baseFilename
  end
  option = "uf"
  if (keepManifest)
    `cd #{jarDir} && jar xf #{jarFile} META-INF/MANIFEST.MF 2&>1`
#    puts `ls -l #{jarDir}/META-INF/MANIFEST.MF`
    option = "umf #{jarDir}/META-INF/MANIFEST.MF"
  end
#  puts "Copying #{replacementFile} to #{File.join(jarDir, targetFile)}"
  File.cp(replacementFile, File.join(jarDir, targetFile) )
#  puts "jar #{option} #{jarFile} -C #{jarDir} #{targetFile}"
  results = `jar #{option} #{jarFile} -C #{jarDir} #{targetFile} 2&>1`
#  puts "result from jar: #{results}"
#  puts "========================"
  File.rm_all(jarDir)
end

$jarDir = "/tmp/config.#{rand(100000)}"
$jarChanges = 0
$jarCreated=false
$tmpFilesDeleted=true
$jarFile="#{CIP}/configs/security/securityservices_config.jar"
$referenceJarFile="#{CIP}/configs/security/reference/securityservices_config.jar"

def searchDir(dir, filename, dirok = true) 
  Dir.foreach(dir) { |file|
    fullName = File.join(dir, file)
    stat = File.stat(fullName);
    if (filename == file && (dirok || !stat.directory?))
      return fullName;
    end
    if (file == "." || file == "..")
      next;
    end
    if (stat.directory?)
      subFile = searchDir(fullName, filename, dirok)
      if (subFile)
        return subFile
      end
    end
  }
  return nil
end

def rebuildTempDir()
  if (!FileTest.exists?($jarDir)) 
    Dir.mkdirs($jarDir);
  end
  # the invariant is that the tmp dir has the desired files in the jar file
  # but we keep cleaning it up...
  if ($tmpFilesDeleted) then
    if ($jarCreated) then                     # get them from the latest jar file
#      puts "cd #{$jarDir} && jar xvf #{$jarFile}"
      `cd #{$jarDir} && jar xvf #{$jarFile}`
    else                                      # get them from the reference file
#      puts "cd #{$jarDir} && jar xvf #{$referenceJarFile}"
      `cd #{$jarDir} && jar xvf #{$referenceJarFile}`
    end
  end
  $tmpFilesDeleted = false
end

def getConfigFile(fileName = nil)
  rebuildTempDir()
  if (fileName == nil)
    return nil;
  end
  return searchDir($jarDir, fileName, false);
end

def scheduleConfigChange(fileName, contents=nil)
#  puts("Schedule changes for  file #{fileName}")
  toFile = getConfigFile(File.basename(fileName))
  if (toFile == nil) 
    toFile = File.join($jarDir, File.basename(fileName));
  end
  if (contents == nil)
    File.cp(fileName, toFile);
  else
    File.open(toFile, "w") { |file|
      file.write(contents);
    }
  end
  $jarChanges = $jarChanges + 1
end

def commitConfigChanges()
  if ($jarChanges == 0)
    return nil
  end
  rebuildTempDir()
#  puts "cd #{$jarDir} && jar cf #{$jarFile} ."
  `cd #{$jarDir} && jar cf #{$jarFile} .`
  $jarCreated=true
  signJar($jarFile, "#{CIP}/operator/signingCA_keystore",            
          "privileged")
  File.rm_all($jarDir);
  $tmpFilesDeleted=true
  $jarChanges = 0;
end

