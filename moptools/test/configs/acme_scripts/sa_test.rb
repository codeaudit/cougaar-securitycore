$:.unshift "../src/lib"
$:.unshift "../../acme_service/src/redist"

require 'cougaar/scripting'
require 'ultralog/scripting'
require 'csitest/scripting'

Cougaar::ExperimentMonitor.enable_stdout

# Name your experiment something interesting
Cougaar.new_experiment("AMHExperiment").run {

# Fix the path to the XML file for your setup
  do_action "LoadSocietyFromXML", "/home/mabrams/cougaar/10.2/rules/new-TINY-1AD-TRANS-1359.xml"
# Put in your jabber server name
  do_action "StartJabberCommunications", "acme_console", "puma3","c0ns0le"

# Print out CougaarEvents as they come in - useful for debugging
  do_action "GenericAction" do |run|
     run.comms.on_cougaar_event do |event|
       puts event
       # or print whatever
     end
  end

# Make sure our hosts are running
  do_action "VerifyHosts"
  #
  # Adding the optional "true" argument will turn on debugging
  do_action "StartSociety"
  #
# Now run the society
  wait_for  "OPlanReady", "60"
  do_action "SendOPlan"
  wait_for  "GLSReady"
  # See the note at the bottom of the TinySetup page for instructions on
  # adding a sleep here if you get errors
  do_action "StartTesting"
  do_action "PublishGLSRoot"
  wait_for  "PlanningComplete"
  #
  wait_for  "Command", "shutdown"
  do_action "StopTesting"
  do_action "AnalyzeResults"
  do_action "StopSociety"
  do_action "StopCommunications"
}