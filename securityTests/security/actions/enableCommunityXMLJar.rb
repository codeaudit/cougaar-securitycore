#!/usr/bin/ruby

module Cougaar
  module Actions
    class EnableCommunityXMLJar < Cougaar::Action
      def initialize(run)
        super(run)
      end

      def perform
          @communityJar = "#{CIP}/configs/common/communities.xml.jar"
          run.info_message "Enabling #{@communityJar}"
          if !File.exists?("#{@communityJar}")
            File.rename("#{@communityJar}.orig", "#{@communityJar}")
          end
      end
    end
  end
end
