#!/usr/bin/ruby

module Cougaar
  module Actions
    class EnableCommunityXMLJar < Cougaar::Action
      def initialize(run)
        super(run)
      end

      def perform
          @communityJar = "#{CIP}/configs/common/communities.xml.jar"
          @communityXml = "#{CIP}/configs/common/communities.xml"
          run.info_message "Enabling #{@communityJar} and #{@communityXml}"
          if !File.exists?("#{@communityJar}")
            File.rename("#{@communityJar}.orig", "#{@communityJar}")
          end
	  if !File.exists?("#{@communityXml}")
            File.rename("#{@communityXml}.orig", "#{@communityXml}")
          end

      end
    end
  end
end
