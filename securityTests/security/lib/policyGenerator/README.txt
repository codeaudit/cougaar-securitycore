
This directory contains the elements of a policy generation tool.
Right now we are focussing on communiction policies describing who can
talk to who.  It currently is for testing purposes only.  In order to
run simulate.rb (which tests whether a previously run society would
have satisfied the policy), you need to construct a data set.  The
data set is a subdirectory consisting of

   dataset/
      mySociety.xml
      mySociety.rb
      myCommunity.xml
      log4jlogs/
         the logs from the society.  These must have been run with
         the MessageReaderAspect installed and with logging for the
         MessageReaderAspect set to DEBUG.  This provides the data
         needed to determine which agent communications actually
         occured in the society.  The MessageReaderAspect also
         supplies some additional data that can be useful in determining
         what agents were doing when they communicated.

Running the tool 

         generateSending.rb dataset

will construct the Sending.rb file in the dataset directory. This
file is used by simulate.rb.

Running the tool simulate.rb will constuct policies and test whether
the society would have satisfied those policies.


---------------------------------
Typical steps to construct a database directory:
   1. Get the society ruby script, the baseline and the host file from
      the run in question.
   2. Edit them to only transform the society and generate the
      mySociety.rb and myCommunities.xml files
        In the baseline remember to
          set the host file
          remove everything after StartCommunications
        In the Society ruby remember to 
          remove the archive line
          remove the scripts        
          you may need $:.unshift File.join(CIP, 'csmart', 'lib')??
   3. run the society ruby script
   4. If you are going to analyze logs 
      A. put them in log4jlogs
      B. run generateSending.rb dataset to generate the Sending.rb
   5. otherwise just touch Sending.rb
