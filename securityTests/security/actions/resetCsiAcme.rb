#!/usr/bin/ruby

module Cougaar
  module Actions
    class ResetCsiAcme < Cougaar::Action
      def initialize(run)
        super(run)
        @hosts = BuildCsiHostFile::getHosts
        puts "ResetCsiAcme"
        @scriptName="#{CIP}/resetAcme.sh"
        file = File.open(@scriptName ,"w") { |file|
          file.write <<END
#!/bin/sh
killall -9 java ; /etc/init.d/acme stop
rm -f /tmp/*.xml ; rm -f /tmp/*.sig ; rm -f /tmp/*.jar ; rm -f /tmp/*.sql
/etc/init.d/acme start
END
        }
        File.chmod(0755, @scriptName)
      end

      def perform
        @hosts.each { |host|
          @run.info_message "Reset ACME at #{host}"
          invoke_remote host, @scriptName
        }
      end
      def invoke_remote(host, cmdstr)
        cmd = "ssh #{host} sudo \"#{cmdstr}\""
        @run.info_message "#{cmd}"
        `#{cmd}`
      end
    end
  end
end
