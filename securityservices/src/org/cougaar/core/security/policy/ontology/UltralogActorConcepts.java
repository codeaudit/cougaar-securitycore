package org.cougaar.core.security.policy.ontology;

import kaos.ontology.util.OntologyLanguageTagSelector;

/**
 * Class generated automatically by kaos.tools.OWLOntologyJavaMapper.
 * Provides static methods to obtain URI's for the core KAoS ontology concepts and properties.
 */
final public class UltralogActorConcepts
{
	final private static String UltralogActorOwlURL = "http://ontology.ihmc.us/Ultralog/UltralogActor.owl#";

    public static String UltralogActorOwlURL() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActorOwlURL); 
	}

	// Concepts
    public static String UltralogPlugins() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActorOwlURL + "UltralogPlugins"); 
	}

	// Properties
    public static String roleOfPlugin() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(UltralogActorOwlURL + "roleOfPlugin"); 
	}

	// Instances
}
