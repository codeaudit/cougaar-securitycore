
module Cougaar
  module Actions
    class SecurityArchiveSetup < Cougaar::Action
      def initialize(run)
	super(run)
	@security_archives_dir = [
	  "#{CIP}/workspace",
	  "#{CIP}/workspace/auditlogs",
	  "#{CIP}/workspace/test",
	  "#{CIP}/workspace/test/stacktraces",
	  "#{CIP}/workspace/security",
	  "#{CIP}/workspace/security/keystores",
	  "#{CIP}/workspace/security/mopresults",
	]
      end

      def perform()
	@security_archives_dir.each { |d|
	  Dir.mkdir(d) unless File.exist?(d)
	}
      end
    end # class
  end #module Actions
end # module Cougaar
