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


package org.cougaar.core.security.policy.enforcers.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.repository.TargetInstanceDescription;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.ontology.ActorClassesConcepts;
import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.ConfigFinder;

/**
 * By definition, everything in here is a temporary hack that should
 * go.  The code is not complete until this class is obsolete. Some
 * hacks are worse than others.  Every member of this class should
 * come with a comment explaining what needs to be done to get rid of
 * it.
 */
public class HardWired {

  /**
   * Ontology name for authorization with no credentials and weak protection
   */
  public static final String NO_AUTH = 
    EntityInstancesConcepts.EntityInstancesOwlURL() + "NoAuth";

  /**
   * Ontology name for authorization with no credentials and strong protection
   */
  public static final String NO_AUTH_SSL = 
    EntityInstancesConcepts.EntityInstancesOwlURL() + "NoAuthSSL";

  /**
   * Ontology name for authorization with password and weak protection
   */
  public static final String PASSWORD_AUTH = 
    EntityInstancesConcepts.EntityInstancesOwlURL() + "Password";

  /**
   * Ontology name for authorization with password and strong protection
   */
  public static final String PASSWORD_AUTH_SSL = 
    EntityInstancesConcepts.EntityInstancesOwlURL() + "PasswordSSL";

  /**
   * Ontology name for authorization with certificate and strong protection
   */
  public static final String CERT_AUTH_SSL = 
    EntityInstancesConcepts.EntityInstancesOwlURL() + "CertificateSSL";

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
    = {"http://localhost/~redmond/Extras/Names.owl#Tom",
       "http://localhost/~redmond/Extras/Names.owl#Dick",
       "http://localhost/~redmond/Extras/Names.owl#Harry"};

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
      return ActorClassesConcepts.ActorClassesOwlURL() + role;
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
                      UltralogActionConcepts.usedAuthenticationLevel(),
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
