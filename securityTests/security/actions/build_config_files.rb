#
# Actions to:
#  - Build a signed jar file containing the communities.xml file.
#  - Build signed jar files containing the node XML files.

# Utility class to package society configuration jar files in signed jar files
class JarPackagerUtility
  def JarPackagerUtility.jarAndSign(filepath, subdir)
    jar_file_name = "#{filepath}.jar"
    cmd_jar = "cd #{subdir} ; jar cf #{jar_file_name} #{filepath}"
    cmd_jarsign = "cd #{subdir} ; jarsigner -keystore $CIP/operator/security/signingCA_keystore -storepass keystore #{jar_file_name} privileged"

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

      @java_class =    @node.classname
      @arguments =     @node.prog_parameters
      @env =           @node.env_parameters
      @jvm_props =     @node.parameters
      @commandLine = "java #{@jvm_props.join(' ')} #{@java_class} #{@arguments.join(' ')} >& $CIP/workspace/nodelogs/#{@node_name}.log"
      saveCommandLine
    rescue
      puts $!
      puts $!.backtrace
    end
  end

  def saveCommandLine
    scriptName = "#{@society_config_dir}/#{@node_name}.sh"
    file = File.open(scriptName ,"w") { |file|
       file.write <<END
#!/bin/sh
#{@commandLine}
END
    }
    File.chmod(0755, scriptName)
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
        cmd_copy = "cp #{@savedCommunityFile} #{@society_config_dir}/#{@community_file_name}"
        `#{cmd_copy}`
        file = JarPackagerUtility.jarAndSign("communities.xml", @society_config_dir)
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
