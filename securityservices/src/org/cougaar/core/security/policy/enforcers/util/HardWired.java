/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package org.cougaar.core.security.policy.enforcers.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.ConfigFinder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.repository.TargetInstanceDescription;

/**
 * By definition, everything in here is a temporary hack that should
 * go.  The code is not complete until this class is obsolete. Some
 * hacks are worse than others.  Every member of this class should
 * come with a comment explaining what needs to be done to get rid of
 * it.
 */
public class HardWired {

  /**
   * Ontology name for very weak crypto
   */
  public static final String WEAK_CRYPTO = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "WeakProtection";

  /**
   * Ontology name for secret crypto
   */
  public static final String SECRET_CRYPTO = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "SecretProtection";

  /**
   * Ontology name for strong crypto
   */
  public static final String STRONG_CRYPTO = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "NSAApprovedProtection";

  /**
   * Ontology name for authorization with no credentials and weak protection
   */
  public static final String NO_AUTH = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "NoAuth";

  /**
   * Ontology name for authorization with no credentials and strong protection
   */
  public static final String NO_AUTH_SSL = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "NoAuthSSL";

  /**
   * Ontology name for authorization with password and weak protection
   */
  public static final String PASSWORD_AUTH = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "Password";

  /**
   * Ontology name for authorization with password and strong protection
   */
  public static final String PASSWORD_AUTH_SSL = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "PasswordSSL";

  /**
   * Ontology name for authorization with certificate and strong protection
   */
  public static final String CERT_AUTH_SSL = 
    org.cougaar.core.security.policy.enforcers.ontology.jena.
    EntityInstancesConcepts.EntityInstancesDamlURL + "CertificateSSL";

  /**
   * The string of users is so that the Servlet Enforcer can say
   * that he has some actors that he is enforcing policy for.  This
   * should go when some combination of the following are fixed:
   * <ul>
   * <li> there is a user login that is hooked to the enforcer,
   * <li> there is an alternative policy distribution scheme and
   * <li> we are using SemanticMatchers to determine if a user is in
   * a role.
   */
  public final static String [] users
    = {"http://localhost/~redmond/Extras/Names.daml#Tom",
       "http://localhost/~redmond/Extras/Names.daml#Dick",
       "http://localhost/~redmond/Extras/Names.daml#Harry"};

  private static LoggingService _log;

  public static void setServiceBroker(ServiceBroker sb) {
    if (_log == null) {
      _log = (LoggingService) sb.getService( new HardWired(),
                                             LoggingService.class, null );
    }
  }


  /**
   * There will need to ultimately be a mechanism that grabs roles
   * from the system.  It could be that this will ultimately be in
   * an ontology but this has only happened when adequate support
   * exists so that the system names roles using the ontology.
   */

  public final static String kaosRoleFromRole(String role)
  {
    return org.cougaar.core.security.policy.enforcers.ontology.jena.
      ActorClassesConcepts.ActorClassesDamlURL + role;
  }

  /**
   * This one actually might not be too bad.  But there will need to be some
   * scheme for translating verbs as detected in messages to verbs defined by 
   * the ontologies.
   */
  public final static String  kaosVerbFromVerb(String verb)
  {
    if (verb == null) {
      verb = "NoVerb";
    }
    verb = org.cougaar.core.security.policy.enforcers.ontology.jena.
      EntityInstancesConcepts.EntityInstancesDamlURL
      + verb;
    if (hasSubjectValues.contains(verb)) {
      return verb;
    } else { 
      return org.cougaar.core.security.policy.enforcers.ontology.jena.
        EntityInstancesConcepts.EntityInstancesDamlURL + "OtherVerb";
    }
  }

  /**
   * We need to map high level names for encryption schemes to what
   * they mean at a lower level.  This definitely should not be done
   * this low a level of abstraction.  It could be done in a policy
   * ontology somewhere with a naming scheme convention that people
   * can use to relate the ontology names for crypto schemes to the
   * real names.
   */
  public static final AuthSuite noAuth =
    new AuthSuite(null,
                  AuthSuite.authNoAuth);

  public static final AuthSuite sslNoAuth =
    new AuthSuite(SSLCipherSuites.STRONG_SUITES,
                  AuthSuite.authNoAuth);

  public static final AuthSuite passwordAuth =
    new AuthSuite(null,
                  AuthSuite.authPassword);

  public static final AuthSuite sslPasswordAuth =
    new AuthSuite(SSLCipherSuites.STRONG_SUITES,
                  AuthSuite.authPassword);

  public static final AuthSuite certAuth =
    new AuthSuite(SSLCipherSuites.STRONG_SUITES,
                  AuthSuite.authCertificate);

  static {
    noAuth.getSSL().add("plain");
    passwordAuth.getSSL().add("plain");
  }

  public static final CipherSuite nsaApproved;
  static {
    nsaApproved = new CipherSuite();
    nsaApproved.addSymmetric("RC4#128");
    nsaApproved.addSymmetric("DESede#128");
    nsaApproved.addSymmetric("Blowfish#128");
    nsaApproved.addSymmetric("AES#128");
    nsaApproved.addAsymmetric("RSA/ECB/PKCS1Padding");
    nsaApproved.addSignature("MD5withRSA");
  }

  public static final CipherSuite secretCrypto;
  static {
    secretCrypto = new CipherSuite();
    secretCrypto.addSymmetric("DES");
    secretCrypto.addAsymmetric("RSA/ECB/PKCS1Padding");
    secretCrypto.addSignature("MD5withRSA");
  }


  public static final CipherSuite weakCrypto;
  static {
    weakCrypto = new CipherSuite();
    weakCrypto.addSymmetric("plain");
    weakCrypto.addAsymmetric("none");
    weakCrypto.addSignature("none");
  }

  
  public final static CipherSuite ulCiphersFromKAoSProtectionLevel(Set ciphers)
  {
    CipherSuite cs = new CipherSuite();
    for(Iterator cipherIt = ciphers.iterator(); cipherIt.hasNext();) {
      String cipher = (String) cipherIt.next();
      if (cipher.equals(WEAK_CRYPTO) ) {
        cs.addAll(weakCrypto);
      } else if (cipher.equals(STRONG_CRYPTO)) {
        cs.addAll(nsaApproved);
      } else if (cipher.equals(SECRET_CRYPTO)) {
        cs.addAll(secretCrypto);
      } else {
        continue;  // I guess he is getting less than he wanted...
      }
    }
    return cs;
  }

  public final static AuthSuite ulAuthSuiteFromKAoSAuthLevel(Set ciphers)
  {
    AuthSuite as = new AuthSuite();
    for(Iterator cipherIt = ciphers.iterator(); cipherIt.hasNext();) {
      String cipher = (String) cipherIt.next();
      if (cipher.equals(NO_AUTH)) {
        as.addAll(noAuth);
      } else if (cipher.equals(NO_AUTH_SSL)) {
        as.addAll(sslNoAuth);
      } else if (cipher.equals(PASSWORD_AUTH)) {
        as.addAll(passwordAuth);
      } else if (cipher.equals(PASSWORD_AUTH_SSL)) {
        as.addAll(sslPasswordAuth);
      } else if (cipher.equals(CERT_AUTH_SSL)) {
        as.addAll(certAuth);
      }
    }
    return as;
  }

  /**
   * This will later be calculated by the directory service.
   */
  public final static Set hasSubjectValues;
  static {
    hasSubjectValues = new HashSet();
    Set rawVerbs = 
      readDamlDecls("Ontology-EntityInstances.daml", 
                    "<ultralogEntity:ULContentValue rdf:ID=");
    for (Iterator rawVerbIt = rawVerbs.iterator();
         rawVerbIt.hasNext();) {
      String verb = (String) rawVerbIt.next();
      hasSubjectValues.add(
                    org.cougaar.core.security.policy.enforcers.ontology.jena.
                    EntityInstancesConcepts.EntityInstancesDamlURL 
                    + verb);
    }
  }

  /**
   * This will later be calculated by the directory service.
   */
  public final static HashSet usedProtectionLevelValues;
  static {
    usedProtectionLevelValues = new HashSet();
    usedProtectionLevelValues.add(WEAK_CRYPTO);
    usedProtectionLevelValues.add(SECRET_CRYPTO);
    usedProtectionLevelValues.add(STRONG_CRYPTO);
  }


  /**
   * This will later be calculated by the directory service.
   */
  public final static HashSet usedAuthenticationLevelValues;
  static {
    usedAuthenticationLevelValues = new HashSet();
    usedAuthenticationLevelValues.add(NO_AUTH);
    usedAuthenticationLevelValues.add(NO_AUTH_SSL);
    usedAuthenticationLevelValues.add(PASSWORD_AUTH);
    usedAuthenticationLevelValues.add(PASSWORD_AUTH_SSL);
    usedAuthenticationLevelValues.add(CERT_AUTH_SSL);
  }

  /**
   * This matching of the real cryptographic concepts with the
   * ontology concepts will take some work.
   */
  public static boolean addAuthSuiteTarget(Set targets, 
                                           String sslCipher,
                                           int authLevel)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Trying to add targets for cipher suite: " + 
                 sslCipher);
    }
    String auth;
    if (certAuth.contains(sslCipher, authLevel)) {
      auth = CERT_AUTH_SSL;
    } else if (sslPasswordAuth.contains(sslCipher, authLevel)) {
      auth = PASSWORD_AUTH_SSL;
    } else if (passwordAuth.contains(sslCipher, authLevel)) {
      auth = PASSWORD_AUTH;
    } else if (sslNoAuth.contains(sslCipher, authLevel)) {
      auth = NO_AUTH_SSL;
    } else if (noAuth.contains(sslCipher, authLevel)) {
      auth = NO_AUTH;
    } else {
      return false;
    }

    Set authSet = Collections.singleton(auth);
    if (_log.isDebugEnabled()) {
      _log.debug("Adding to auth target: " + auth);
    }
    targets.add( new TargetInstanceDescription(
                      org.cougaar.core.security.policy.enforcers.ontology.jena.
                      UltralogActionConcepts._usedAuthenticationLevel_,
                      auth ) );
    return true;
  }

  public final static Set readDamlDecls(String filename, String key)
  {
    try {
      Set vars = new HashSet();
      ConfigFinder cf = ConfigFinder.getInstance();
      File file = cf.locateFile(filename);
      Reader reader = new FileReader(file);
      BufferedReader breader = new BufferedReader(reader);
      String line;
      while ((line = breader.readLine()) != null) {
        if (line.indexOf(key) != -1) {
          int start = line.indexOf('\"');
          int end   = line.indexOf('\"', start + 1);
          vars.add(line.substring(start+1,end));
        }
      }
      return vars;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

}
