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
    public static final String Role = OntologyLanguageTagSelector.selectLanguageForTag(UltralogGroupOwlURL + "Role");
    public static final String Community = OntologyLanguageTagSelector.selectLanguageForTag(UltralogGroupOwlURL + "Community");

    public static String Role() { return Role; };
    public static String Community() { return Community; };

	// Properties


	// Instances

}
