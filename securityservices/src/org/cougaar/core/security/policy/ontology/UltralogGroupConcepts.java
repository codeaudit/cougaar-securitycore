package org.cougaar.core.security.policy.ontology;

import kaos.ontology.util.OntologyLanguageTagSelector;

/**
 * Class generated automatically by kaos.tools.OWLOntologyJavaMapper.
 * Provides static methods to obtain URI's for the core KAoS ontology concepts and properties.
 */
final public class UltralogGroupConcepts
{
	final private static String UltralogGroupOwlURL = "http://ontology.ihmc.us/Ultralog/UltralogGroup.owl#";

    public static String UltralogGroupOwlURL() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogGroupOwlURL); 
	}

	// Concepts
    public static String Role() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogGroupOwlURL + "Role"); 
	}
    public static String Community() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogGroupOwlURL + "Community"); 
	}

	// Properties

	// Instances
}
