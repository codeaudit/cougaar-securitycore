#!/usr/bin/ruby

module Cougaar
  module Actions
    class DisableCommunityXMLJar < Cougaar::Action
      def initialize(run)
        super(run)
      end

      def perform
          @communityJar = "#{CIP}/configs/common/communities.xml.jar"
          run.info_message "Disabling #{@communityJar}"
          if File.exists?("#{@communityJar}")
            File.rename("#{@communityJar}", "#{@communityJar}.orig")
          end
      end
    end
  end
end
