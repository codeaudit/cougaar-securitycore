/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */
package org.cougaar.core.security.crypto.ldap;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.Hashtable;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.KeyManagementException;
import java.security.cert.CertificateException;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.catalina.realm.JNDIRealm;

/**
 * A Realm extension for Tomcat 4.0 that supplies the ability to
 * use ssl, client certificates, and specified TrustStore.            <p>
 *
 * An example SecureJNDIRealm addition to server.xml which uses
 * anonymous binding to the ldap database, but uses a client certificate
 * to present to the LDAP server:
 * <pre>
 *   <Realm className="org.cougaar.secuirty.crypto.ldap.SecureJNDIRealm" 
 *          connectionURL="ldaps://chump:636"
 *          roleBase="dc=roles,dc=nai,dc=com"
 *          roleName="cn"
 *          roleSearch="(uniqueMember={0})"
 *          roleSubtree="false"
 *          userPassword="userPassword"
 *          userPattern="cn={0},dc=nai,dc=com" 
 *          keyStore="/home/gmount/doc/cert2/keystore.db"
 *          keyStorePassword="password"
 *          trustStore="/home/gmount/doc/cert2/keystore.db"
 *          trustStorePassword="password"
 *          debug="-1" />
 * </pre>
 * In addition to the parameters you may supply to Tomcat's JNDIRealm,
 * you may specify any of the following parameters:
 * <table>                                                  <tr><td>
 *   useSSL                                                 </td><td>
 *     Boolean whether ssl is used or not. Default is false. This value
 *     is modified to true if the connectionURL begins with
 *     "ldaps://"                                           </td></tr><tr><td>
 *   keyStore                                               </td><td>
 *     The path to where the keystore for the client certificate
 *     resides.                                             </td></tr><tr><td>
 *   keyStorePassword                                       </td><td>
 *     The password to the keystore where the client certificate
 *     resides. The default is "changeit"                   </td></tr><tr><td>
 *   keyStoreType                                           </td><td>
 *     The type of the keystore where the client certificate
 *     resides. The default is "JKS"                        </td></tr><tr><td>
 *   certificatePassword                                    </td><td>
 *     The password to the client certificate. The default is the
 *     same as the keystore certificate.                    </td></tr><tr><td>
 *   trustStore                                             </td><td>
 *     The file path to the truststore.                     </td></tr><tr><td>
 *   trustStorePassword                                     </td><td>
 *     The password to the truststore. 
 *     The default is "changeit"                            </td></tr><tr><td>
 *   trustStoreType                                         </td><td>
 *     The type of the truststore.
 *     The default is "JKS"                                 </td></tr><tr><td>
 *   sslProtocol                                            </td><td>
 *     The SSL protocol to use when communicating with the LDAP server.
 *     The default is "TLS"                                 </td></tr>
 * </table> 
 *
 * @see org.apache.catalina.realm.JNDIRealm
 * @author George Mount <gmount@nai.com>
 */
public class SecureJNDIRealm extends JNDIRealm {
  
  /** 
   * Boolean value revealing whether or not to communcate with
   * the LDAP server with SSL. 
   */
  protected boolean _useSSL;

  /**
   * The SSL protocol to use when communicating with the LDAP server 
   */
  protected String _sslProtocol = "TLS";

  /** The keystore location for the client SSL certificate. */
  protected String _keystore;
  
  /** The keystore password for the client SSL certificate. */
  protected String _keypass = "changeit";

  /** The certificate password for the client SSL certificate. */
  protected String _certpass;

  /** The keystore type. */
  protected String _keystoreType = "JKS";

  /** The truststore location for server SSL certificates and CA's. */
  protected String _truststore;

  /** The truststore password for server SSL certificates and CA's. */
  protected String _trustpass = "changeit";

  /** The truststore type. */
  protected String _truststoreType = "JKS";

  /** Default constructor */
  public SecureJNDIRealm() {}

  /**
   * Open (if necessary) and return a connection to the configured
   * directory server for this Realm.
   *
   * @exception NamingException if a directory server error occurs
   */
  protected DirContext open() throws NamingException {

    if (context == null) {

      if (debug >= 1)
        log("Connecting to URL " + connectionURL);

      Hashtable env = new Hashtable(11);

      env.put(Context.INITIAL_CONTEXT_FACTORY, contextFactory);
      if (connectionName != null)
        env.put(Context.SECURITY_PRINCIPAL, connectionName);
      if (connectionPassword != null)
        env.put(Context.SECURITY_CREDENTIALS, connectionPassword);
      if (connectionURL != null)
        env.put(Context.PROVIDER_URL, connectionURL);

      if (_useSSL) {
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        
        // set the SSL context server
        if (_keystore != null || _truststore != null) {
          try {
            KeyManager   km[] = null;
            TrustManager tm[] = null;
          
            KeyStore ks = null;
            if (_keystore != null) {
              KeyManagerFactory kmf = KeyManagerFactory.
                getInstance(KeyManagerFactory.getDefaultAlgorithm());
              ks = KeyStore.getInstance(_keystoreType);
              char passphrase[] = _keypass.toCharArray();
              ks.load(new FileInputStream(_keystore), passphrase);

              if (_certpass != null) 
                passphrase = _certpass.toCharArray();

              kmf.init(ks, passphrase);
              km = kmf.getKeyManagers();
            }

            if (_truststore != null) {
              TrustManagerFactory tmf = TrustManagerFactory.
                getInstance(TrustManagerFactory.getDefaultAlgorithm());

              // only get a different keystore if it is different from
              // the certificate keystore
              if (_truststore != _keystore || _trustpass != _keypass) {
                ks = KeyStore.getInstance(_truststoreType);
                char passphrase[] = _trustpass.toCharArray();
                ks.load(new FileInputStream(_truststore), passphrase);
              }

              tmf.init(ks);
              tm = tmf.getTrustManagers();
            }
            SSLContext sslctx = SSLContext.getInstance(_sslProtocol);
            sslctx.init(km, tm, null);
            JNDISSLFactory.init(sslctx);
            env.put("java.naming.ldap.factory.socket", 
                    "org.cougaar.core.security.crypto.ldap.JNDISSLFactory");
          } catch (KeyStoreException ex) {
            throw new NamingException("Problem with the KeyStore: " + 
                                      ex.getMessage());
          } catch (CertificateException ex) {
            throw new NamingException("Bad KeyStore: " + 
                                      ex.getMessage());
          } catch (NoSuchAlgorithmException ex) {
            throw new NamingException("Problem with the supplied algorithm: "+ 
                                      ex.getMessage());
          } catch (UnrecoverableKeyException ex) {
            throw new NamingException("Could not get the client certificate: "+ 
                                      ex.getMessage());
          } catch (KeyManagementException ex) {
            throw new NamingException("Could initialize the KeyManager: "+ 
                                      ex.getMessage());
          } catch (FileNotFoundException ex) {
            throw new NamingException("Could not open the keystore: " + 
                                      ex.getMessage());
          } catch (IOException ex) {
            throw new NamingException("Error reading from the keystore: " + 
                                      ex.getMessage());
          }
        }
      }
      context = new InitialDirContext(env);
    }
    return context;
  }

  /**
   * Set the connection URL for this Realm.
   *
   * @param connectionURL The new connection URL
   */
  public void setConnectionURL(String connectionURL) {
    
    if (connectionURL.startsWith("ldaps://")) {
      setUseSSL(true);
      int colonIndex = connectionURL.indexOf(":",8);
      int slashIndex = connectionURL.indexOf("/",8);
      String host;
      if (slashIndex == -1) slashIndex = connectionURL.length();
      if (colonIndex == -1 || colonIndex > slashIndex) {
        // there is no default port -- change the default
        // port to 636 for ldaps
        if (slashIndex == 0) {
          // there is no host either -- use 0.0.0.0 as host
          host = "0.0.0.0";
        } else {
          host = connectionURL.substring(8,slashIndex);
        }
        connectionURL = "ldap://" + host + ":636" + 
          connectionURL.substring(slashIndex);
      } else {
        connectionURL = "ldap://" + connectionURL.substring(8);
      }
    }
    this.connectionURL = connectionURL;
    
  }

  /**
   *  Get whether or not to use SSL for communication with the
   *  LDAP server 
   */
  public boolean getUseSSL() {
    return _useSSL;
  }

  /** 
   * Set whether or not to use SSL for communication with the
   * LDAP server 
   *
   * @param use Whether to use SSL or not.
   */
  public void setUseSSL(boolean use) {
    _useSSL = use;
  }

  /**
   * Get the KeyStore location for the client certificate
   */
  public String getKeyStore() {
    return _keystore;
  }

  /**
   * Set the KeyStore location for the client certificate
   *
   * @param keystore The file path to the keystore to use
   */
  public void setKeyStore(String keystore) {
    _keystore = keystore;
  }

  /**
   * Get the KeyStore password for the client certificate.
   * The default is "changeit"
   */
  public String getKeyStorePassword() {
    return _keypass;
  }

  /**
   * Set the KeyStore password for the client certificate.
   *
   * @param password The clear text keystore password to use
   */
  public void setKeyStorePassword(String password) {
    _keypass = password;
  }

  /**
   * Get the client certificate password if different from the 
   * KeyStore password
   */
  public String getCertificatePassword() {
    return _certpass;
  }

  /**
   * Set the client certificate password if different from the 
   * KeyStore password
   *
   * @param password The clear text certificate password to use
   */
  public void setCertificatePassword(String password) {
    _certpass = password;
  }

  /**
   * Get the KeyStore type for the client certificate. The
   * default is "JKS"
   */
  public String getKeyStoreType() {
    return _keystoreType;
  }

  /**
   * Set the KeyStore type for the client certificate. 
   *
   * @param type The KeyStore type to use.
   * @see java.security.KeyStore
   */
  public void setKeyStoreType(String type) {
    _keystoreType = type;
  }

  /**
   * Get the TrustStore location for the LDAP server
   */
  public String getTrustStore() {
    return _truststore;
  }

  /**
   * Set the TrustStore location for the LDAP server
   *
   * @param truststore The file path to the truststore
   */
  public void setTrustStore(String truststore) {
    _truststore = truststore;
  }

  /**
   * Get the TrustStore password for the client certificate.
   * The default is "changeit"
   */
  public String getTrustStorePassword() {
    return _trustpass;
  }

  /**
   * Set the TrustStore password for the client certificate.
   *
   * @param password The clear text password to the truststore
   */
  public void setTrustStorePassword(String password) {
    _trustpass = password;
  }

  /**
   * Get the TrustStore type. The default is "JKS"
   */
  public String getTrustStoreType() {
    return _truststoreType;
  }

  /**
   * Set the TrustStore type. The default is "JKS"
   *
   * @param type The TrustSore KeyStore type to use.
   * @see java.security.KeyStore
   */
  public void setTrustStoreType(String type) {
    _truststoreType = type;
  }

  /**
   * Get the SSL protocol to use. The default is "TLS"
   */
  public String getSslProtocol() {
    return _sslProtocol;
  }

  /**
   * Set the SSL protocol to use. The default is "TLS"
   *
   * @param protocol The SSL protocl to use.
   * @see javax.net.ssl.SSLContext
   */
  public void setSslProtocol(String protocol) {
    _sslProtocol = protocol;
  }

}
