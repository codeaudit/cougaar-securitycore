/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
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
    public static final String CommunityAction = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "CommunityAction");
    public static final String WPForward = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPForward");
    public static final String WPUpdateSelf = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdateSelf");
    public static final String CommunityActionSelf = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "CommunityActionSelf");
    public static final String WPUpdateDelegate = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdateDelegate");
    public static final String BlackBoardAccess = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "BlackBoardAccess");
    public static final String WPUpdate = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPUpdate");
    public static final String EncryptedCommunicationActionSelf = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "EncryptedCommunicationActionSelf");
    public static final String ServletAccess = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "ServletAccess");
    public static final String CommunityActionDelegate = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "CommunityActionDelegate");
    public static final String WPLookup = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "WPLookup");

    public static String CommunityAction() { return CommunityAction; };
    public static String WPForward() { return WPForward; };
    public static String WPUpdateSelf() { return WPUpdateSelf; };
    public static String CommunityActionSelf() { return CommunityActionSelf; };
    public static String WPUpdateDelegate() { return WPUpdateDelegate; };
    public static String BlackBoardAccess() { return BlackBoardAccess; };
    public static String WPUpdate() { return WPUpdate; };
    public static String EncryptedCommunicationActionSelf() { return EncryptedCommunicationActionSelf; };
    public static String ServletAccess() { return ServletAccess; };
    public static String CommunityActionDelegate() { return CommunityActionDelegate; };
    public static String WPLookup() { return WPLookup; };

	// Properties
    public static final String usedAuditLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedAuditLevel");
    public static final String forwardTo = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "forwardTo");
    public static final String usedProtectionLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedProtectionLevel");
    public static final String communityTarget = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "communityTarget");
    public static final String hasSubject = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "hasSubject");
    public static final String communityActionType = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "communityActionType");
    public static final String blackBoardAccessObject = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "blackBoardAccessObject");
    public static final String usedAuthenticationLevel = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "usedAuthenticationLevel");
    public static final String accessedServlet = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "accessedServlet");
    public static final String wpAgentEntry = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "wpAgentEntry");
    public static final String community = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "community");
    public static final String blackBoardAccessMode = OntologyLanguageTagSelector.selectLanguageForTag(UltralogActionOwlURL + "blackBoardAccessMode");

    public static String usedAuditLevel() { return usedAuditLevel; };
    public static String forwardTo() { return forwardTo; };
    public static String usedProtectionLevel() { return usedProtectionLevel; };
    public static String communityTarget() { return communityTarget; };
    public static String hasSubject() { return hasSubject; };
    public static String communityActionType() { return communityActionType; };
    public static String blackBoardAccessObject() { return blackBoardAccessObject; };
    public static String usedAuthenticationLevel() { return usedAuthenticationLevel; };
    public static String accessedServlet() { return accessedServlet; };
    public static String wpAgentEntry() { return wpAgentEntry; };
    public static String community() { return community; };
    public static String blackBoardAccessMode() { return blackBoardAccessMode; };

	// Instances

}
