package org.cougaar.core.security.policy.ontology;

import kaos.ontology.util.OntologyLanguageTagSelector;

/**
 * Class generated automatically by kaos.tools.OWLOntologyJavaMapper.
 * Provides static methods to obtain URI's for the core KAoS ontology concepts and properties.
 */
final public class UltralogEntityConcepts
{
	final private static String UltralogEntityOwlURL = "http://ontology.ihmc.us/Ultralog/UltralogEntity.owl#";

    public static String UltralogEntityOwlURL() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL); 
	}

	// Concepts
    public static String PlugInRoles() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "PlugInRoles"); 
	}
    public static String WPAccessType() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPAccessType"); 
	}
    public static String BlackBoardAccessMode() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "BlackBoardAccessMode"); 
	}
    public static String ProtectionLevel() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "ProtectionLevel"); 
	}
    public static String UltralogEntity() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "UltralogEntity"); 
	}
    public static String Servlet() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "Servlet"); 
	}
    public static String AuditLevel() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "AuditLevel"); 
	}
    public static String BlackBoardObjects() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "BlackBoardObjects"); 
	}
    public static String AuthenticationLevel() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "AuthenticationLevel"); 
	}
    public static String ULContentValue() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "ULContentValue"); 
	}

	// Properties

	// Instances
    public static String WPAdd() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPAdd"); 
	}
    public static String WPRemove() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPRemove"); 
	}
    public static String WPChange() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPChange"); 
	}
}
