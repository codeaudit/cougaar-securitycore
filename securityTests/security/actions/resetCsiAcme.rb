#!/usr/bin/ruby

module Cougaar
  module Actions
    class ResetCsiAcme < Cougaar::Action
      def initialize(run)
        super(run)
        @hosts = BuildCsiHostFile::getHosts
        puts "ResetCsiAcme"
        @scriptName="#{CIP}/resetAcme.sh"
        pid = Process.pid
        file = File.open(@scriptName ,"w") { |file|
          file.write <<END
#!/bin/sh
killall -9 java ; /etc/init.d/acme stop 
killall -9 start_acme ; pkill -9 -u root /usr/bin/ruby
rm -f /tmp/*.xml ; rm -f /tmp/*.sig ; rm -f /tmp/*.jar ; rm -f /tmp/*.sql
rm -rf $CIP/workspace/P
rm -rf $CIP/workspace/log4jlogs/*
rm -rf $CIP/workspace/nodelogs/*
rm -rf $CIP/workspace/auditlogs/*
rm -rf $CIP/workspace/security/*
rm -rf $CIP/workspace/jarfiles/*
rm -rf $CIP/workspace/rss/*
rm -rf $CIP/workspace/test/*
sleep 3
/etc/init.d/acme start
END
        }
        File.chmod(0755, @scriptName)
      end

      def perform
        `rm -rf #{CIP}/Logs ; mkdir #{CIP}/Logs ; rm -rf #{CIP}/log/bootstrap/*`
        @hosts.each { |host|
          @run.info_message "Reset ACME at #{host}"
          invoke_remote host, @scriptName
        }
      end
      def invoke_remote(host, cmdstr)
        cmd = "ssh #{host} sudo \"#{cmdstr}\""
        #@run.info_message "#{cmd}"
        `#{cmd}`
      end
    end
  end
end
