#!/usr/bin/ruby



module Cougaar
  module Actions
    class BuildLanSpec < Cougaar::Action
      def initialize(run, nodes)
        super(run)
        @run = run
        @nodes = nodes
      end

      def perform
        stagingdir = "#{CIP}/workspace/NetConfig-#{rand(1000000)}"
        lanFile="#{stagingdir}/LanSpec"
        jarFile="#{CIP}/configs/security/lan_spec.jar"
        signingKeystore="#{CIP}/operator/security/signingCA_keystore"

        Dir.mkdir(stagingdir)
        File.open(lanFile, "w") do |file|
          @nodes.each do |node|
            file.puts(node)
          end
          @run.society.each_agent do |agent|
            if @nodes.include?(agent.node.name) then
              file.puts(agent.name)
            end
          end
        end
        result = `cd #{PathUtility.fixPath(stagingdir)} && jar cf #{PathUtility.fixPath(jarFile)} .`
        result = `jarsigner -keystore #{PathUtility.fixPath(signingKeystore)} -storepass keystore #{PathUtility.fixPath(jarFile)} privileged`
        `rm -rf #{stagingdir}`
      end
    end
  end
end
