$LOAD_PATH.unshift ".."

require 'framework/mergeMopAnalysis'
require 'framework/namedCollection'
require 'framework/securityMop2.4'
require 'framework/securityMopAnalysis'

#name = '/var/export/archive42/analysis_data/sv022/1073166306/mnt/shared/socVA/workspace/security/mops'
#name = '/var/export/archive42/analysis_data/sv022/1073138403/mnt/shared/socVA/workspace/security/mops'

name  = '/var/export/archive42/analysis_data/sv022/1072536669/mnt/shared/socVA/workspace/security/mops'
name2 = '/var/export/archive42/analysis_data/sv022/1073989636/mnt/shared/socVA/workspace/security/mops'
#name3 = '/var/export/archive42/analysis_0210/sv022/1074105575/mnt/shared/socVA/workspace/security/mops'
name3 = name

#name = "logisticsMop/JTG4/mnt/shared/socVA/workspace/security/mops"
#name2 = "logisticsMop/JTG5/mnt/shared/socVA/workspace/security/mops"
#name3 = "logisticsMop/JTG4/mnt/shared/socVA/workspace/security/mops"


=begin
db = PStore.new(name+"/mops")
db.transaction do |db|
  puts db['info']
end
exit
=end


=begin
a = PostSecurityMopAnalysis.new(name)
# convert percentages according to the MOP charts in survivability report
#a.convertScores
#scores = a.getScores
scores = a.getMoeValues
puts
puts scores.inspect
x = a.getXMLData
puts
puts x
exit
=end


a = MergePostSecurityMopAnalysis.new(name, name2, name3)
# convert percentages according to the MOP charts in survivability report
#a.convertScores

scores = a.getMoeValues
x = a.getXMLData

puts "<SurvivabilityMetrics>"
puts x
puts "</SurvivabilityMetrics>"
exit

puts scores.inspect
