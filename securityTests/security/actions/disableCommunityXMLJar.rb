#!/usr/bin/ruby

module Cougaar
  module Actions
    class DisableCommunityXMLJar < Cougaar::Action
      def initialize(run)
        super(run)
      end

      def perform
          @communityJar = "#{CIP}/configs/common/communities.xml.jar"
          @communityXml = "#{CIP}/configs/common/communities.xml"
          run.info_message "Disabling #{@communityJar} and #{@communityXml}"
          if File.exists?("#{@communityJar}")
            File.rename("#{@communityJar}", "#{@communityJar}.orig")
          end
	 if File.exists?("#{@communityXml}")
            File.rename("#{@communityXml}", "#{@communityXml}.orig")
          end
	
      end
    end
  end
end
