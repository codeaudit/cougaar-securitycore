package org.cougaar.core.security.policy.enforcers.util;

import java.io.*;
import java.util.*;

import org.cougaar.core.security.policy.enforcers.ontology.*;
import org.cougaar.core.security.policy.enforcers.util.CipherSuite;
import org.cougaar.core.security.policy.enforcers.util.AuthSuite;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.util.ConfigFinder;

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
    EntityInstancesConcepts.EntityInstancesDamlURL + "WeakProtection";

  /**
   * Ontology name for secret crypto
   */
  public static final String SECRET_CRYPTO = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "SecretProtection";

  /**
   * Ontology name for strong crypto
   */
  public static final String STRONG_CRYPTO = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "NSAApprovedProtection";

  /**
   * Ontology name for authorization with no credentials and weak protection
   */
  public static final String NO_AUTH = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "NoAuth";

  /**
   * Ontology name for authorization with no credentials and strong protection
   */
  public static final String NO_AUTH_SSL = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "NoAuthSSL";

  /**
   * Ontology name for authorization with password and weak protection
   */
  public static final String PASSWORD_AUTH = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "Password";

  /**
   * Ontology name for authorization with password and strong protection
   */
  public static final String PASSWORD_AUTH_SSL = 
    EntityInstancesConcepts.EntityInstancesDamlURL + "PasswordSSL";

  /**
   * Ontology name for authorization with certificate and strong protection
   */
  public static final String CERT_AUTH_SSL = 
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

  public final static Set stripDomainFromRoles(Set roles)
  {
    Set strippedRoles = new HashSet();

    for (Iterator roleIt = roles.iterator();
         roleIt.hasNext();) {
      String role = (String) roleIt.next();
      int index = role.indexOf('\\');
      if (index != -1) {
        role = role.substring(index+1);
      } 
      strippedRoles.add(role);
    }
    return strippedRoles;
  }

  /**
   * There will need to ultimately be a mechanism that grabs roles
   * from the system.  It could be that this will ultimately be in
   * an ontology but this has only happened when adequate support
   * exists so that the system names roles using the ontology.
   */

  public final static String kaosRoleFromRole(String role)
  {
    return ActorClassesConcepts.ActorClassesDamlURL + role;
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
    return (EntityInstancesConcepts.EntityInstancesDamlURL
            + verb);
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
    nsaApproved.addSymmetric("RC4");
    nsaApproved.addSymmetric("DESede");
    nsaApproved.addSymmetric("Blowfish");
    nsaApproved.addSymmetric("AES");
    nsaApproved.addAsymmetric("RSA");
    nsaApproved.addSignature("MD5withRSA");
  }

  public static final CipherSuite secretCrypto;
  static {
    secretCrypto = new CipherSuite();
    secretCrypto.addSymmetric("DES");
    secretCrypto.addAsymmetric("RSA");
    secretCrypto.addSignature("MD5withRSA");
  }


  public static final CipherSuite weakCrypto;
  static {
    weakCrypto = new CipherSuite();
    weakCrypto.addSymmetric("DES");
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
      hasSubjectValues.add(EntityInstancesConcepts.EntityInstancesDamlURL 
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
    targets.add( new TargetInstanceDescription( UltralogActionConcepts.
                                                _usedAuthenticationLevel_,
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
