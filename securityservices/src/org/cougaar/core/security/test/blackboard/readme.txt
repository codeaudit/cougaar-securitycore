Testing Blackboard:
To Test the compromise of a blackboard:
	Add the ComporomiseBlakcboardServlet, /core/security/blackboard/BlackobardComrisePlugin to the Blackboard
	To simulate the detection of a compromise and to start the test, request the servlet: /compromiseBlackboard

For all of the following test you also need to add the BlackboardTestManagerServlet

	
To Test the Adding of an Org Activity by a Legitimate Plugin:
	Add the LegitimateBlackboardAddPlugin (with query and add priviledges org activity privledges)
	
To Test the Modification of the Org Activity by a Legit plugin:
	Add the LegitimateBlackboardModifyPlugin (with query and modify priviledges for org activities)
	
To Test the Modification of the Org Activity by a Legit plugin:
	Add the LegitimateBlackboardDeletePlugin (with query and delete priviledges for org activies)
	