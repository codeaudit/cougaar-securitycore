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
final public class EntityInstancesConcepts
{
	final private static String EntityInstancesOwlURL = "http://ontology.ihmc.us/Ultralog/Names/EntityInstances.owl#";

    public static String EntityInstancesOwlURL() 
	{
		return OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL); 
	}

	// Concepts


	// Properties


	// Instances
    public static final String NoAuthSSL = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "NoAuthSSL");
    public static final String BlackBoardAccessQuery = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessQuery");
    public static final String BlackBoardAccessRead = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessRead");
    public static final String WeakProtection = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "WeakProtection");
    public static final String PasswordSSL = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "PasswordSSL");
    public static final String BlackBoardAccessRemove = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessRemove");
    public static final String BlackBoardAccessWrite = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessWrite");
    public static final String NoAuth = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "NoAuth");
    public static final String BlackBoardAccessAdd = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessAdd");
    public static final String NoAudit = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "NoAudit");
    public static final String NoVerb = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "NoVerb");
    public static final String otherBlackboardObjects = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "otherBlackboardObjects");
    public static final String Password = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "Password");
    public static final String NSAApprovedProtection = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "NSAApprovedProtection");
    public static final String SecretProtection = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "SecretProtection");
    public static final String OtherVerb = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "OtherVerb");
    public static final String BlackBoardAccessChange = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessChange");
    public static final String BlackBoardAccessCreate = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "BlackBoardAccessCreate");
    public static final String CertificateSSL = OntologyLanguageTagSelector.selectLanguageForTag(EntityInstancesOwlURL + "CertificateSSL");

    public static String NoAuthSSL() { return NoAuthSSL; };
    public static String BlackBoardAccessQuery() { return BlackBoardAccessQuery; };
    public static String BlackBoardAccessRead() { return BlackBoardAccessRead; };
    public static String WeakProtection() { return WeakProtection; };
    public static String PasswordSSL() { return PasswordSSL; };
    public static String BlackBoardAccessRemove() { return BlackBoardAccessRemove; };
    public static String BlackBoardAccessWrite() { return BlackBoardAccessWrite; };
    public static String NoAuth() { return NoAuth; };
    public static String BlackBoardAccessAdd() { return BlackBoardAccessAdd; };
    public static String NoAudit() { return NoAudit; };
    public static String NoVerb() { return NoVerb; };
    public static String otherBlackboardObjects() { return otherBlackboardObjects; };
    public static String Password() { return Password; };
    public static String NSAApprovedProtection() { return NSAApprovedProtection; };
    public static String SecretProtection() { return SecretProtection; };
    public static String OtherVerb() { return OtherVerb; };
    public static String BlackBoardAccessChange() { return BlackBoardAccessChange; };
    public static String BlackBoardAccessCreate() { return BlackBoardAccessCreate; };
    public static String CertificateSSL() { return CertificateSSL; };
}
