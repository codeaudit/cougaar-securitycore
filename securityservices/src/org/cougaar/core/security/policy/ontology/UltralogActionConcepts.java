package org.cougaar.core.security.policy.ontology;

import kaos.ontology.util.OntologyLanguageTagSelector;

/**
 * Class generated automatically by kaos.tools.OWLOntologyJavaMapper.
 * Provides static methods to obtain URI's for the core KAoS ontology concepts and properties.
 */
final public class UltralogActionConcepts
{
	final private static String UltralogActionOwlURL = "http://ontology.ihmc.us/Ultralog/UltralogAction.owl#";

    public static String UltralogActionOwlURL() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL); 
	}

	// Concepts
    public static String WPUpdateSelf() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdateSelf"); 
	}
    public static String BlackBoardAccess() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "BlackBoardAccess"); 
	}
    public static String ServletAccess() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "ServletAccess"); 
	}

	// Properties
    public static String wpAccessType() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "wpAccessType"); 
	}
    public static String usedAuditLevel() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedAuditLevel"); 
	}
    public static String usedProtectionLevel() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedProtectionLevel"); 
	}
    public static String hasSubject() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "hasSubject"); 
	}
    public static String blackBoardAccessObject() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "blackBoardAccessObject"); 
	}
    public static String usedAuthenticationLevel() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedAuthenticationLevel"); 
	}
    public static String accessedServlet() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "accessedServlet"); 
	}
    public static String blackBoardAccessMode() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "blackBoardAccessMode"); 
	}

	// Instances
}
