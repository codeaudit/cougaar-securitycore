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
    public static final String WPForward = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPForward");
    public static final String WPUpdateSelf = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdateSelf");
    public static final String WPUpdateDelegate = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdateDelegate");
    public static final String BlackBoardAccess = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "BlackBoardAccess");
    public static final String WPUpdate = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdate");
    public static final String ServletAccess = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "ServletAccess");
    public static final String WPLookup = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPLookup");

    public static String WPForward() { return WPForward; };
    public static String WPUpdateSelf() { return WPUpdateSelf; };
    public static String WPUpdateDelegate() { return WPUpdateDelegate; };
    public static String BlackBoardAccess() { return BlackBoardAccess; };
    public static String WPUpdate() { return WPUpdate; };
    public static String ServletAccess() { return ServletAccess; };
    public static String WPLookup() { return WPLookup; };

	// Properties
    public static final String usedAuditLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedAuditLevel");
    public static final String forwardTo = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "forwardTo");
    public static final String usedProtectionLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedProtectionLevel");
    public static final String hasSubject = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "hasSubject");
    public static final String blackBoardAccessObject = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "blackBoardAccessObject");
    public static final String usedAuthenticationLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedAuthenticationLevel");
    public static final String accessedServlet = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "accessedServlet");
    public static final String wpAgentEntry = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "wpAgentEntry");
    public static final String blackBoardAccessMode = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "blackBoardAccessMode");

    public static String usedAuditLevel() { return usedAuditLevel; };
    public static String forwardTo() { return forwardTo; };
    public static String usedProtectionLevel() { return usedProtectionLevel; };
    public static String hasSubject() { return hasSubject; };
    public static String blackBoardAccessObject() { return blackBoardAccessObject; };
    public static String usedAuthenticationLevel() { return usedAuthenticationLevel; };
    public static String accessedServlet() { return accessedServlet; };
    public static String wpAgentEntry() { return wpAgentEntry; };
    public static String blackBoardAccessMode() { return blackBoardAccessMode; };

	// Instances

}
