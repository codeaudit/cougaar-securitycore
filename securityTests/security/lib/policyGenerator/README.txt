
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
