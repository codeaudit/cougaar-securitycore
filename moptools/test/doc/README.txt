
Blackboard Security Services Test Project

================================================================================
Overview
================================================================================

This project includes a small suite of tools for testing the
UltraLog security security services blackboard access controls. Two test plugins
are included, one legitimate and the other malicious, that subscribe to
OrgActivity objects.   If a malicious plugin is able to access the OrgActivity
object or a legitimate plugin is unable to access the OrgActivity object then it
is considered a test failure.  The plugins keep track of the number of tests
run, the number passed and the number failed.  If a test fails then the plugin
creates an IDMEF event.    The plugins begin execution when they receive a start
task and stop when they receive a stop task.  A servlet is provided that can be
used to generate these tasks.  A Ruby script is also included that can
automatically execute this servlet as part of the larger experirement being
executed.  Each plugin query's the blackboard every 10 seconds by default.  The
plugins listen to the black board test plugin operating mode.  Changing this
mode's value will change the query rate of the plugin.  A servlet that can
change the operating mode is also included in the project.  When a plugin
receives the stop testing notification it dumps the results of the test to a
database.  At this point a single Analayzer plugin executes.  The analayzer
plugin reads the database and outputs the results for every agent to a CSV and
HTML files.

================================================================================
Building, Installing, and Running the Tests (make sure the cougaar environment
variables are set
================================================================================

1.)From the base directory of the project run:   ant
2.)From the base directory of the project run:   ant install
3.)copy the XML configuration for the test and the rules included in this project
   to a directory
4.)run COUGAAR_INSTALL_PATH/csmart/config/bin/transform_society.rb -i
your_society.xml -r ./5.)Include the start and stop ruby scripts (see sa_test.rb
for an example) in your ACME script6.)Execute the test (ruby
your_test_script.rb)

================================================================================
Changing the Operating mode 
================================================================================

To change the Operating Mode for the test plugins execute
the AEChangeModeServelt.  This can be down by going to the servlet's URL or by a
script.  The following is a sample of URL to change the operating
mode:
$AGENT/aeChangeMode?change=OperatingMode&name=BlackboardOMTestPlugin.BLACKBOARD_OPERATING_MODE&value=1000

================================================================================
Test Results
===============================================================================

The test results are stored in a Database, CSV files, and
HTML formats.  The createTest.sql script creates the "testresults" database.  The database parameters and 
the directory where the CSV and HTML files are to be dumped are embedded as arguments to the Malicious 
and Legitimate plugins identified in their rules.  The agents where the plugins will be loaded are specified 
in a list within the rule.  The Test suite includes two servlets called by the "StartTesting" and 
"EndTesting" and "AnalyzeResults" Actions.  The "AnalyzeResults" action calls the AnalyzerServlet which
then creates the HTML and CSV file dumps.  The AnalyzerServlet needs to be loaded on the "NCA" agent as
well as at least one of the other plugins (Legitimate and Malicious). To change this modify the "AnalyzeResults"
Action in the scripting.rb file.  