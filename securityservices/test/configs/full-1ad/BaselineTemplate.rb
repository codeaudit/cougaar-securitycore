#CIP = ENV['CIP']
# Uncomment the following two lines if working in the CSI testbed
$:.unshift File.join(CIP, 'csmart', 'lib')
require 'security/lib/scripting'

require 'cougaar/scripting'
require 'ultralog/scripting'

include Cougaar

HOSTS_FILE = Ultralog::OperatorUtils::HostManager.new.get_hosts_file

Cougaar::ExperimentMonitor.enable_stdout
Cougaar::ExperimentMonitor.enable_logging

Cougaar.new_experiment().run(parameters[:run_count]) {
  set_archive_path parameters[:archive_dir]

  do_action "LoadSocietyFromScript", parameters[:society_file]

  host_file = HOSTS_FILE
  #host = @hostname unless host
  Dir.glob(File.join(".", "example-hosts-secureMV.xml")).each do |file|
    ts = Cougaar::SocietyBuilder.from_xml_file(file).society
    host_file = file
  end
#  do_action "LayoutSociety", parameters[:layout_file], HOSTS_FILE
  do_action "LayoutSociety", parameters[:layout_file], host_file

  do_action "TransformSociety", false, *parameters[:rules]
  if (!parameters[:community_rules].nil?)
    do_action "TransformSociety", false, *parameters[:community_rules]
  end

at :transformed_society

  do_action "SaveCurrentSociety", "mySociety.xml"
  do_action 'SaveCurrentCommunities', 'myCommunity.xml'

  do_action "StartCommunications"

  # Uncomment the following line if working in the CSI testbed
  do_action "SetAcmeParameters", { 'jvm_path' => '/usr/java/j2sdk1.4.2_03/bin/java' }
  do_action "SetAcmeUser"
  do_action "BuildConfigJarFiles"

  do_action "CleanupSociety"
  do_action "Sleep", 10.seconds

  do_action "VerifyHosts"

  do_action "DeployCommunitiesFile"
  do_action "KeepSocietySynchronized"
  do_action "InstallCompletionMonitor"
  do_action "WatchAgentPersists"
  do_action "MarkForArchive", "#{CIP}/workspace/nodelogs", "*.log", "Node stderr & stdout"
  do_action "MarkForArchive", "#{CIP}/workspace/log4jlogs", "*.log", "Log4j node log"
  do_action "MarkForArchive", "#{CIP}/workspace/log4jlogs", "*.?*log", "Log4j other log"
  do_action "MarkForArchive", "#{CIP}/configs/nodes", "*xml", "XML node config files"

  do_action "InstallReportChainWatcher"

at :setup_run

  do_action "StartSociety"

at :wait_for_initialization

  wait_for  "ReportChainReady", 30.minutes
  
at :society_running
  
  wait_for  "GLSConnection", false
  do_action "Sleep", 30.seconds
  wait_for  "NextOPlanStage", 10.minutes
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Initial Planning Phase  Stage-1#########"

at :during_stage_1

  wait_for "SocietyQuiesced", 2.hours do
    include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage1"
    do_action "StopSociety"
    do_action "CleanupSociety"
    do_action "StopCommunications"
  end

  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage1"
  
at :after_stage_1

  do_action "InfoMessage", "Advancing time to AUG 14 (C-1), 1 day steps, quiescing between steps"
  do_action "AdvanceTime", 4.days
  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "PreStage2"

at :before_stage_2

  wait_for  "NextOPlanStage", 1.hour
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Next Planning Phase  Stage-2  ########"
  do_action "InfoMessage", "########  OPlan Deployment Date Change for 2-BDE #######"

at :during_stage_2

  wait_for "SocietyQuiesced", 2.hours do
    include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage2"
    do_action "StopSociety"
    do_action "CleanupSociety"
    do_action "StopCommunications"
  end

  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage2"

at :after_stage_2

  do_action "InfoMessage", "Advancing time to AUG 30 (C+15), 1 day steps, quiescing between steps"
  do_action "AdvanceTime", 16.days
  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "PreStage3_4"

at :before_stage_3

  wait_for  "NextOPlanStage", 1.hour
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Next Planning Phase  Stage-3 #########"
  do_action "InfoMessage", "########  OPlan OPTEMPO Change for 2-BDE on C+17 #########"

at :before_stage_4

  wait_for  "NextOPlanStage", 1.hour
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Next Planning Phase Stage-4 #########"
  do_action "InfoMessage", "########  UA OPlan deployment + day 1.         #########"

at :during_stages_3_4

  wait_for "SocietyQuiesced", 2.hours do
    include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage3_4"
    do_action "StopSociety"
    do_action "CleanupSociety"
    do_action "StopCommunications"
  end

  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage3_4"

at :after_stages_3_4

  do_action "InfoMessage", "Advancing time to Sep 4 (C+20), daily steps, quiescing between steps"
  do_action "AdvanceTime", 5.days
  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "PreStage5_6"

at :before_stage_5

  wait_for  "NextOPlanStage", 1.hour
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Next Planning Phase Stage5  ########"
  do_action "InfoMessage", "########  UA OPlan change for Pursuit and Urban Assault #######"

at :before_stage_6

  wait_for  "NextOPlanStage", 1.hour
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Next Planning Phase Stage-6 #########"
  do_action "InfoMessage", "########  1-BDE OPTEMPO changes from Medium to High  #########"
  
at :during_stages_5_6

  wait_for "SocietyQuiesced", 2.hours do
    include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage5_6", true
    do_action "StopSociety"
    do_action "CleanupSociety"
    do_action "StopCommunications"
  end
  
  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage5_6", true

at :after_stages_5_6

  do_action "InfoMessage", "Advancing time to Sep 5 (C+21), daily steps, quiescing between steps"
  do_action "AdvanceTime", 1.day
  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "PreStage7", true

at :before_stage_7

  wait_for  "NextOPlanStage", 1.hour
  do_action "PublishNextStage"
  do_action "InfoMessage", "########  Starting Next Planning Phase Stage-7 #########"
  do_action "InfoMessage", "########  UA begins Air Assault   #########"

at :during_stage_7

  wait_for "SocietyQuiesced", 2.hours do
    include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage7", true
    do_action "StopSociety"
    do_action "CleanupSociety"
    do_action "StopCommunications"
  end

  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage7", true

at :after_stage_7

  do_action "InfoMessage", "Advancing time to Sep 7 (C+23), daily steps, quiescing between steps"
  do_action "AdvanceTime", 2.days
  do_action "InfoMessage", "Advancing time to Sep 10 (C+26), daily steps, quiescing between steps"
  do_action "AdvanceTime", 3.days

  include "#{CIP}/csmart/lib/isat/post_stage_data.inc", "Stage7_C26", true

at :end_of_run

  do_action "FreezeSociety"

at :society_frozen

  do_action "Sleep", 30.seconds
  do_action "StopSociety"
  
at :society_stopped

  do_action "CleanupSociety"
  do_action "StopCommunications"
}
