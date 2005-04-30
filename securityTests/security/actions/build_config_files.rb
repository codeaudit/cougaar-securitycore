#
# Actions to:
#  - Build a signed jar file containing the communities.xml file.
#  - Build signed jar files containing the node XML files.

require 'security/lib/path_utility'

# Utility class to package society configuration jar files in signed jar files
class JarPackagerUtility
  def JarPackagerUtility.jarAndSign(filepath, subdir)
    jar_file_name = "#{filepath}.jar"
    #puts "PWD:  #{`pwd`}"
    cmd_jar = "cd #{PathUtility.fixPath(subdir)} && jar cf #{PathUtility.fixPath(jar_file_name)} #{PathUtility.fixPath(filepath)}"
    puts "build_config_files: #{cmd_jar}" if $VerboseDebugging
    p1 = "#{$CIP}/operator/security/signingCA_keystore"
    cmd_jarsign = "cd #{PathUtility.fixPath(subdir)} && jarsigner -keystore #{PathUtility.fixPath(p1)} -storepass keystore #{PathUtility.fixPath(jar_file_name)} privileged"
    #puts cmd_jarsign

    `#{cmd_jar}`
    `#{cmd_jarsign}`
     return "#{subdir}/#{jar_file_name}"
  end
end

class NodeConfigUtility
  def initialize(node, subdir)
    @node =          node
    @node_name =     @node.name
    @xml_filename =  "#{@node_name}.xml"
    @society_config_dir = subdir

  end

  def to_xml_file
    File.open("#{@society_config_dir}/#{@xml_filename}", "wb") {|file| file.puts(@node.to_xml)}
  end

  def saveSignedXmlJarFile
    begin
      # Edit the society per the current configuration
      # Set just the filename, not the path
      @node.override_parameter("-Dorg.cougaar.society.file", @xml_filename.split(File::SEPARATOR)[-1])

      # Save as XML file
      to_xml_file
      JarPackagerUtility.jarAndSign(@xml_filename, @society_config_dir)
      File.unlink("#{@society_config_dir}/#{@xml_filename}")

      @java_class =    @node.classname
      @arguments =     @node.prog_parameters
      @env =           @node.env_parameters
      @jvm_props =     @node.parameters

      # Save cygwin command line
      convertToCywin(@jvm_props)
      @commandLineCygwin = "java #{@jvm_props.join(' ')} #{@java_class} #{@arguments.join(' ')} >& $CIP/workspace/nodelogs/#{@node_name}.log"
      saveCommandLine("-cygwin")

      # Save UNIX command line
      convertToUnix(@jvm_props)
      @commandLine = "java #{@jvm_props.join(' ')} #{@java_class} #{@arguments.join(' ')} >& $CIP/workspace/nodelogs/#{@node_name}.log"
      saveCommandLine("")

      # Save Windows command line
      convertToDos(@java_class)
      convertToDos(@arguments)
      convertToDos(@env)
      convertToDos(@jvm_props)
      propertiesInFile = []
      extractArgumentsToPropertyFile(@jvm_props, propertiesInFile)

      @commandLineDos = "@java #{@jvm_props.join(' ')} #{@java_class} #{@arguments.join(' ')} 2> %COUGAAR_INSTALL_PATH%\\workspace\\nodelogs\\#{@node_name}-stderr.log > %COUGAAR_INSTALL_PATH%\\workspace\\nodelogs\\#{@node_name}-stdout.log"

      saveCommandLineDos
    rescue
      puts $!
      puts $!.backtrace
    end
  end

  # Build the .sh file for Unix.
  def convertToUnix(arguments)
    arguments.each do |arg|
      if arg.index('Xbootclasspath') != nil || arg.index('java.class.path') != nil
        # Convert separator
        arg.gsub!(/\;/, ':') 
      end
    end
  end

  # Build the .sh file for Cygwin.
  def convertToCywin(arguments)
    arguments.each do |arg|
      if arg.index('Xbootclasspath') != nil || arg.index('java.class.path') != nil
        # Convert separator
        arg.gsub!(/:/, '\;') 
        # However, "bootclasspath/a" and "bootclasspath/p" should be followed by ":"
        arg.gsub!(/bootclasspath\/a\\;/, 'bootclasspath/a:')
        arg.gsub!(/bootclasspath\/p\\;/, 'bootclasspath/p:')
        arg.gsub!(/bootclasspath\\;/, 'bootclasspath:')
      end
    end
  end

  # Save properties to file in a format that the bootstrapper can read.
  def savePropertiesToFile(propertyFile, propertiesInFile)
    #puts "Saving properties to #{propertyFile}..."
    file = File.open(propertyFile ,"w") { |file|
      propertiesInFile.each do |prop|
        prop = prop.gsub(/^-D/, '')
        file.write(prop + "\n")
      end
    }
  end
  
  # Extract arguments that are not needed by the bootstrapper.
  # This is needed on Windows 2000, as the command line length is
  # limited to 2047 characters.
  # On Windows XP, the length of the commmand line is limited to 9191 characters
  # For additional information, see:
  #   http://support.microsoft.com/default.aspx?scid=kb;en-us;830473
  #
  def extractArgumentsToPropertyFile(arguments, propertiesInFile)
    propertyFile = "#{@society_config_dir}/#{@node_name}.prop"
    # A list of arguments that should be kept on the command line
    # They are needed by the bootstrapper.
    argumentsNeeded = [
       "^-Dorg\\.cougaar\\.bootstrap\\..*",
       "^-Dorg\\.cougaar\\.install\\.path",
       "^-Dorg\\.cougaar\\.workspace",
       "^-Dorg\\.cougaar\\.system\\.path",
       "^-Dorg\\.cougaar\\.class\\.path",
       "^-Djava\\.class\\.path",
       "^-Djava\\.security\\..*",
       "^-Djava\\.io\\..*",
       "^-X.*",
    ]
    regexpNeeded = []
    argumentsNeeded.each do |neededArg|
       regexpNeeded << Regexp.new(neededArg)
    end
		parsedArgs = []
		
    arguments.each do |arg|
      needed = false
      regexpNeeded.each do |neededArg|
        if neededArg =~ arg
          needed = true
          #puts "#{arg} - #{neededArg}"
          break
        end
      end
      if !needed
        #puts "Argument #{arg} is NOT needed by bootstrapper"
        arg.gsub!(/%COUGAAR_INSTALL_PATH%/, CIP)
        arg.gsub!(/\\/, '/')
        propertiesInFile << arg
      else
        #puts "Argument #{arg} is needed by bootstrapper"
        parsedArgs << arg
      end
    end
    parsedArgs << "-Dorg.cougaar.properties.url=file:#{@node_name}.prop"
    arguments.clear
	  arguments.concat(parsedArgs)
	  
    savePropertiesToFile(propertyFile, propertiesInFile)
  end
  
  # Build the .bat file for Windows. This is hacky but it should work.
  def convertToDos(arguments)
    arguments.each do |arg|
      arg.gsub!(/\$COUGAAR_INSTALL_PATH/, '%COUGAAR_INSTALL_PATH%')
      arg.gsub!(/\$CIP/, '%COUGAAR_INSTALL_PATH%')
      arg.gsub!(/\\$\\/, '$')
      arg.gsub!(/\\/, '')
      a = arg.downcase
      if a.index('http:') == nil \
           && a.index('https:') == nil \
           && a.index('file:') == nil \
           && a.index('org.cougaar.core.society.starttime') == nil
        arg.gsub!(/\//, '\\')
      end
      arg.gsub!(/bootclasspath\\/, 'bootclasspath/')
      if arg.index('Xbootclasspath') != nil || arg.index('java.class.path') != nil
        # Convert separator
        arg.gsub!(/:/, ';') 
        # However, "bootclasspath/a" and "bootclasspath/p" should be followed by ":"
        arg.gsub!(/bootclasspath\/a\;/, 'bootclasspath/a:')
        arg.gsub!(/bootclasspath\/p\;/, 'bootclasspath/p:')
        arg.gsub!(/bootclasspath\;/, 'bootclasspath:')
      end
      #puts arg
    end
  end

  def saveCommandLine(suffix)
    scriptName = "#{@society_config_dir}/#{@node_name}#{suffix}.sh"
    file = File.open(scriptName ,"w") { |file|
       file.write <<END
#!/bin/bash
mkdir -p $COUGAAR_INSTALL_PATH/workspace/nodelogs
mkdir -p $COUGAAR_INSTALL_PATH/workspace/log4jlogs
END
       if (suffix != "")
         file.write <<END
export COUGAAR_INSTALL_PATH=`cygpath -m $CIP`
export CIP=`cygpath -m $CIP`
#{@commandLineCygwin}
END
       else
         file.write <<END
#{@commandLine}
END
       end
    }
    File.chmod(0755, scriptName)
  end

  def saveCommandLineDos
    scriptName = "#{@society_config_dir}/#{@node_name}.bat"
    file = File.open(scriptName ,"w") { |file|
       file.write <<END
@mkdir %COUGAAR_INSTALL_PATH%\\workspace
@mkdir %COUGAAR_INSTALL_PATH%\\workspace\\log4jlogs
@mkdir %COUGAAR_INSTALL_PATH%\\workspace\\nodelogs
#{@commandLineDos}
END
    }
  end

end

module Cougaar
  module Actions
    class BuildSignedCommunityJarFile < Cougaar::Action
      # file: the name of the community membership file.
      #    do_action 'SaveCurrentCommunities', 'myCommunity.xml' should have been called
      # before invoking this action.
      # The signed jar file will be saved in a subdirectory 'subdir'.
      def initialize(run, file="myCommunity.xml", subdir="society_config")
	super(run)
        @savedCommunityFile = file
        @community_file_name = "communities.xml"
        @society_config_dir = subdir

        Dir.mkdir(@society_config_dir) unless File.exist?(@society_config_dir)
      end

      def perform()
        p1 = "#{@society_config_dir}/#{@community_file_name}"
        File.cp(@savedCommunityFile, p1)
        file = JarPackagerUtility.jarAndSign("communities.xml", @society_config_dir)
        File.unlink("#{@society_config_dir}/#{@community_file_name}")
        @run.info_message "Community file saved under #{file}"
      end
    end # class

    class BuildSignedNodeJarFiles < Cougaar::Action
      def initialize(run, subdir="society_config")
	super(run)
        @society_config_dir = subdir
        Dir.mkdir(@society_config_dir) unless File.exist?(@society_config_dir)
      end

      def perform()
        time = Time.now.gmtime
        @run.society.each_node do |node|
          node.replace_parameter(/Dorg.cougaar.core.society.startTime/, "-Dorg.cougaar.core.society.startTime=\"#{time.strftime('%m/%d/%Y %H:%M:%S')}\"")
        end
        add_cougaar_event_params
        configure_all_nodes
      end

      def add_cougaar_event_params
        @run.society.each_active_host do |host|
          host.each_node do |node|
            node.add_parameter("-Dorg.cougaar.event.host=127.0.0.1")
            node.add_parameter("-Dorg.cougaar.event.port=5300")
            node.add_parameter("-Dorg.cougaar.event.experiment=#{@run.name}")
          end
        end
      end

      def configure_all_nodes
        nodes = []
        @run.society.each_active_host do |host|
          host.each_node do |node|
            nameserver = false
            host.each_facet(:role) do |facet|
              nameserver = true if facet[:role].downcase=="nameserver"
            end
            if nameserver
              nodes.unshift node
            else
              nodes << node
            end
          end
        end
        nodes.each do |node|
          buildNodeXmlFile(node)
        end
      end

      def buildNodeXmlFile(node)
#        node_society = Cougaar::Model::Society.new( "society-for-#{node.name}" ) do |society|
#          society.add_host( node.host.name ) do |host|
#            host.add_node( node.clone(host) )
#          end
#        end
#        node_society.remove_all_facets
        @run.info_message "Building node configuration file for #{node.name}"
        #@run.info_message "#{node_society.to_ruby}"
        n = NodeConfigUtility.new(node, @society_config_dir)
        n.saveSignedXmlJarFile
      end
    end # class

  end #module Actions
end # module Cougaar
