#!/usr/bin/env ruby

$LOAD_PATH.unshift '../..'

require 'security/lib/scripting'
#require 'security/lib/doIrb'

db = PStore.new("#{ENV['CIP']}/workspace/security/mops/mops")
@version = @datestring = @date = @info = @summary = @scores = @raw = @supportingData = nil
db.transaction do |db|
  @version = db['pstoreVersion']
  @datestring = db['datestring']
  @date = db['date']
  @info = db['info']
  @summary = db['summary']
  @scores = db['scores']
  @raw = db['raw']
  @supportingData = db['supportingData']
end

puts @scores.inspect
doIrb

#puts @info
