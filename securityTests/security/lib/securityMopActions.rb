module Cougaar
  module Actions
    class StartTcpCapture < Cougaar::Action
      attr_accessor :hostnames, :hosts, :agents

      def initialize(run, agents)
        super(run)
        @agents = agents
      end

      def perform
        SecurityMop2_3.instance.startTcpCapture(@agents)
      end
    end # class StartTcpCapture
  end # module Actions
end # module Cougaar

