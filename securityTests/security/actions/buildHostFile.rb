#!/usr/bin/ruby

module Cougaar
  module Actions
    class BuildCsiHostFile < Cougaar::Action
      @@hosts = nil

      def initialize(run, hostfilename="example-hosts-secureMV.xml")
        super(run)
        user = ENV["USER"]
        hostsMap = {
          'mluu'     => ["aspen", "apricot", "peach", "olive", "almond"],
          'srosset'  => ["sycamore", "eucalyptus", "rose", "cypress", "beech"],
          'tredmond' => ["pine", "lemon", "yew", "tea", "cherry"],
          'rtripath' => ["elm", "birch", "pear", "palm", "apple"],
          'rliao1'   => ["willow", "chestnut", "ash", "hemlock", "pecan"],
        }
        @@hosts = hostsMap[user]
        #puts @@hosts
        @hostFileName = hostfilename
      end

      def perform
        buildHostFile()
      end

      def BuildCsiHostFile.getHosts
        @@hosts
      end

      def buildHostFile()
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
        }
      end
    end
  end
end
