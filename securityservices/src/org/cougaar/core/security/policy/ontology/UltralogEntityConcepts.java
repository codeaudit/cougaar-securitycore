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
    public static final String PlugInRoles = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "PlugInRoles");
    public static final String WPAccessType = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPAccessType");
    public static final String BlackBoardAccessMode = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "BlackBoardAccessMode");
    public static final String ProtectionLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "ProtectionLevel");
    public static final String UltralogEntity = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "UltralogEntity");
    public static final String Servlet = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "Servlet");
    public static final String AuditLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "AuditLevel");
    public static final String BlackBoardObjects = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "BlackBoardObjects");
    public static final String AuthenticationLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "AuthenticationLevel");
    public static final String ULContentValue = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "ULContentValue");

    public static String PlugInRoles() { return PlugInRoles; };
    public static String WPAccessType() { return WPAccessType; };
    public static String BlackBoardAccessMode() { return BlackBoardAccessMode; };
    public static String ProtectionLevel() { return ProtectionLevel; };
    public static String UltralogEntity() { return UltralogEntity; };
    public static String Servlet() { return Servlet; };
    public static String AuditLevel() { return AuditLevel; };
    public static String BlackBoardObjects() { return BlackBoardObjects; };
    public static String AuthenticationLevel() { return AuthenticationLevel; };
    public static String ULContentValue() { return ULContentValue; };

	// Properties


	// Instances
    public static final String WPAdd = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPAdd");
    public static final String WPChange = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPChange");
    public static final String WPRemove = OntologyLanguageTagSelector.selectLanguageForTag(UltralogEntityOwlURL + "WPRemove");

    public static String WPAdd() { return WPAdd; };
    public static String WPChange() { return WPChange; };
    public static String WPRemove() { return WPRemove; };
}
