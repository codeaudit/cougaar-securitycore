#!/usr/bin/ruby

module Cougaar
  module Actions
    class BuildCsiHostFile < Cougaar::Action
      @@hosts = nil
      @@hostsFound = false

      # "host-layout-file.xml"
      def initialize(run, hostfilename)
        super(run)
        @hostFileName = hostfilename
      end

      def initialize(hostfilename)
        @hostFileName = hostfilename
      end

      def perform
        buildHostFile()
      end

      def BuildCsiHostFile.getHosts
        @@hosts
      end

      def hostFileBuilt?
        @@hostsFound
      end

      def buildHostFile()
        user = ENV["USER"]
        hostsMap = {
          'mluu'     => ["aspen", "apricot", "peach", "olive", "almond"],
          'srosset'  => ["sycamore", "eucalyptus", "rose", "walnut", "beech"],
          'tredmond' => ["pine", "lemon", "yew", "cypress", "cherry"],
          'rtripath' => ["elm", "birch", "pear", "palm", "apple"],
          'rliao1'   => ["willow", "chestnut", "ash", "hemlock", "pecan"],
          'umemphis'   => ["tea", "corn", "mango", "balsam", "redwood"],
          'default'  => ["host_1", "host_2", "host_3", "host_4", "host_5"],
        }
        if hostsMap[user] != nil
          @@hosts = hostsMap[user]
          @@hostsFound = true
        else
          @@hosts = hostsMap['default']
          @@hostsFound = false
        end
        #puts @@hosts

        #puts @hostFileName
        file = File.open(@hostFileName ,"w") { |file|
          file.write <<END
<?xml version="1.0"?>
<society name='foo.com-hosts'  
  xmlns:xsi='http:/www.w3.org/2001/XMLSchema-instance' 
  xsi:noNamespaceSchemaLocation='http:/www.cougaar.org/2003/society.xsd'>
  <host name='fig'>
    <facet service="NFS"/>
  </host>
  <host name='peach'>
    <facet service="SMTP"/>
    <facet service="jabber"/>
  </host>
  <host name='#{@@hosts[0]}'>
    <facet service="operator"/>
    <facet service="acme"/>
  </host>
END
          first = true
          @@hosts.each { |host|
            if (first) 
              first = false
            else 
              file.write <<END
  <host name='#{host}'>
    <facet service="acme"/>
  </host>
END
            end
          } 
          file.write <<END
</society>
END
          file.flush
        }
      end
    end
  end
end
