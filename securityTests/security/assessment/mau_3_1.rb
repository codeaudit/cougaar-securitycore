##
#  <copyright>
#  Copyright 2002 System/Technology Devlopment Corp.
#  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the Cougaar Open Source License as published by
#  DARPA on the Cougaar Open Source Website (www.cougaar.org).
#
#  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
#  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
#  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
#  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
#  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
#  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
#  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#  PERFORMANCE OF THE COUGAAR SOFTWARE.
# </copyright>
#
=begin
require 'cougaar/scripting'
require 'ultralog/scripting'

module Cougaar

  module Actions

    class GetMAU31Data < Cougaar::Action
      def initialize(run, logfile)
        super(run)
        @logfile = logfile
      end
      
      def perform
        mauData = ::Assessment::TimingData.new(@logfile)
        duration = mauData.get_data
        duration.each { |key, value|
          Cougaar.logger.info "Time taken for #{key} is #{value} sec"
        }
      end

    end

  end

end
=end
module Assessment

  ##
  # This class wraps MAU 3.1 data from script log file.
  #
  class TimingData
    StartStr =
    {
      'Planning'   => 'Finished: PublishNextStage',
      'BasicAggQuery' => 'Starting: AggAgentQueryBasic',
      'ShortfallAggQuery' => 'Starting: AggAgentQueryShortfall',
      'JP8AggQuery' => 'Starting: AggAgentQueryJP8',
      'DataGrabber' => 'Starting: ConnectToDatagrabber',
      'CnCcalcPlugin'   => 'Starting: LogCnCData'
    }

    EndStr =
    {
      'Planning'   => 'Done: SocietyQuiesced',
      'BasicAggQuery' => 'Finished: AggAgentQueryBasic',
      'ShortfallAggQuery' => 'Finished: AggAgentQueryShortfall',
      'JP8AggQuery' => 'Finished: AggAgentQueryJP8',
      'DataGrabber' => 'Finished: ConnectToDatagrabber',
      'CnCcalcPlugin'   => 'Done: CnCLoggingComplete'
    }

    def initialize(logfile)
      @logfile = logfile
    end

    def get_data
      if ( FileTest.exists?(@logfile) && FileTest.readable?(@logfile) )
        f = File.open(@logfile, "r")
        startTime = {}
        endTime = {}
        duration = {}
        f.each { |line|
          found = false
          StartStr.each { |key, value|
            if ( (m = /^\[INFO\] (\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) :: \[.*\]\s+#{value}.*/.match(line)) != nil )
              t = Time.local(m[1].to_i, m[2].to_i, m[3].to_i,
                             m[4].to_i, m[5].to_i, m[6].to_i)
              startTime[key] = t
              found = true
              break
            end
          }
          if (!found)
            EndStr.each { |key, value|
              if ( (m = /^\[INFO\] (\d\d\d\d)-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d) :: \[.*\]\s+#{value}.*/.match(line)) != nil )
                t = Time.local(m[1].to_i, m[2].to_i, m[3].to_i,
                               m[4].to_i, m[5].to_i, m[6].to_i)
                endTime[key] = t
                break
              end
            }
          end
        }
        startTime.each_key { |key|
          if ( endTime.has_key?(key) )
            diff = endTime[key] - startTime[key]
            duration[key] = diff
            #puts "Time taken for #{key} is #{diff} sec"
          end
        } 
      else
        puts "Can not open file #{@logfile}"
      end
      return duration
    end

  end

end

if $0==__FILE__
  timingData = ::Assessment::TimingData.new(ARGV[0])
  duration = timingData.get_data
  duration.each { |key, value|
    puts "Time taken for #{key} is #{value} sec"
  }
end
