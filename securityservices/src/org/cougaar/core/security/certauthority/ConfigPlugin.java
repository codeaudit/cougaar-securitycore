/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
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
package org.cougaar.core.security.certauthority;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.certauthority.servlet.CAIdentityClientImpl;
import org.cougaar.core.security.certauthority.servlet.CAInfo;
import org.cougaar.core.security.config.PolicyHandler;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.policy.CertificateAttributesPolicy;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.provider.SecurityComponent;
import org.cougaar.core.security.services.crypto.CertificateCacheService;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.util.NodeInfo;
import org.cougaar.core.security.util.ServletRequestUtil;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.identity.AgentIdentityService;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import sun.security.x509.X500Name;


/**
 *
 *
 */
public class ConfigPlugin
  extends SecurityComponent {
  //extends ComponentPlugin {
  /**
   */
  protected LoggingService  log;
  protected ServiceBroker _sb;
  protected KeyRingService keyRingService;
  protected ConfigParserService configParser;
  protected CryptoClientPolicy cryptoClientPolicy;
  protected CertificateCacheService cacheservice;
  protected BindingSite bindingSite;

  private String caDN = null;
  private String ldapURL = null;
  private String upperCA = null;
  public static String httpport = null;
  private String httpsport = null;

  public void setBindingSite(BindingSite bs) {
    bindingSite = bs;
  }

  public void setState(Object loadState) {}
  public Object getState() {return null;}

  public synchronized void unload() {
    super.unload();
    // unload services in reverse order of "load()"
    //ServiceBroker sb = bindingSite.getServiceBroker();
    // release services
  }

  public void load() {
    super.load();
    _sb = bindingSite.getServiceBroker();

    log = (LoggingService) _sb.getService(this, LoggingService.class, null);

    keyRingService = (KeyRingService)
      _sb.getService(this,
					    KeyRingService.class,
					    null);

    configParser = (ConfigParserService)
      _sb.getService(this,
					    ConfigParserService.class,
					    null);
    if (configParser == null) {
      String s = "Unable to get config parser service. This is probably due to a configuration issue";
      log.error(s);
      throw new RuntimeException(s);
    }
    cacheservice=(CertificateCacheService)
        _sb.getService(this, CertificateCacheService.class, null);
    SecurityPropertiesService sps = (SecurityPropertiesService)
      _sb.getService(this, SecurityPropertiesService.class, null);
    SecurityPolicy[] sp =
      configParser.getSecurityPolicies(CryptoClientPolicy.class);
    cryptoClientPolicy = (CryptoClientPolicy) sp[0];

    httpport = sps.getProperty("org.cougaar.lib.web.http.port", null);
    httpsport = System.getProperty("org.cougaar.lib.web.https.port", null);

    execute();
  }

  protected void execute() {
    // check whether the policy can be modified (only for first time unzip & run)
    // determined by the field isCertificateAuthority as undefined
    // if the CA with the DN already in trust store then it is done

    if (caDN != null && caDN.length() != 0) {
      try {
	if (log.isDebugEnabled()) {
	  log.debug("Generating key for:" + caDN);
	}
        X500Name dname = new X500Name(caDN);
        List list = cacheservice.getCertificates(dname);
        if (list != null && list.size() != 0) {
          if (log.isDebugEnabled()) {
            log.debug("crypto policy already configured.");
          }

          return;
        }

      // need to set default cert attribute policy, so that normal node
      // can use that as their trusted policy
        CertificateAttributesPolicy certAttribPolicy =
          cryptoClientPolicy.getCertificateAttributesPolicy();
        certAttribPolicy.ou = dname.getOrganizationalUnit();
        certAttribPolicy.o = dname.getOrganization();
        certAttribPolicy.l = dname.getLocality();
        certAttribPolicy.st = dname.getState();
        certAttribPolicy.c = dname.getCountry();
      } catch (Exception ex) {
        if (log.isWarnEnabled()) {
          log.warn("Cannot complete CA key generation.", ex);
        }
        return;
      }

      cryptoClientPolicy.setIsCertificateAuthority(true);
    }
    if (upperCA != null) {
      addTrustedPolicy(upperCA);
    }
    else {
      cryptoClientPolicy.setIsRootCA(true);
      checkOrMakeIdentity(null, "");
    }

  }

  public void setParameter(Object o) {
    //Collection l = getParameters();
    Logger logger = LoggerFactory.getInstance().createLogger(this);

    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() == 0 || l.size() > 3) {
      if (logger == null) {
	throw new RuntimeException("Unable to get LoggingService");
      }
      logger.warn("Incorrect number of parameters. Format (caDN, ldapURL, [caURL])");
    }
    Iterator it = l.iterator();

    try {
      caDN = (String)it.next();
      if (it.hasNext()) {
	ldapURL = (String)it.next();
      }
      else {
	ldapURL = "";
      }
    } catch (Exception ex) {
      throw new RuntimeException("Parameter incorrect: " + caDN + " : " + ldapURL);
    }

    if (logger.isDebugEnabled()) {
      logger.debug("CA DN: " + caDN + " - LDAP: " + ldapURL);
    }

    if (l.size() > 2) {
      // this is not a root CA, get trusted ca policy
      // input is CAhost:CAagent, not complete URL
      upperCA = (String)it.next();
    }
  }

  protected void addTrustedPolicy(String param) {
    CARequestThread t = new CARequestThread(param);
    t.start();
  }

  class CARequestThread
    extends Thread {
    String infoURL;
    String requestURL;
    int waittime = 5000;

    public CARequestThread(String param) {
      String cahost = param.substring(0, param.indexOf(':'));
      int agentindex = param.indexOf(':');
      String caagent = param.substring(agentindex+1, param.length());

      // if httpport param is given use it
      int portindex = caagent.indexOf(':');
      if (portindex != -1) {
        portindex += agentindex + 1;
        caagent = param.substring(agentindex+1, portindex);
        httpport = param.substring(portindex + 1, param.lastIndexOf(':'));
        httpsport = param.substring(param.lastIndexOf(':')+1, param.length());
        if (log.isDebugEnabled()) {
          log.debug("agent: " + caagent + " / " + httpport + " / " + httpsport);
        }
      }

      infoURL = "http://" + cahost + ":" +
        httpport + "/$" + caagent + cryptoClientPolicy.getInfoURL();
      if (httpsport == null || httpsport.equals("-1")) {
        requestURL = "http://" + cahost + ":" + httpport;
      }
      else {
        requestURL = "https://" + cahost + ":" + httpsport;
      }
      requestURL += "/$" + caagent + cryptoClientPolicy.getRequestURL();
      //System.out.println("infoURL: " + infoURL + " : requestURL " + requestURL);

      try {
        String waitPoll = System.getProperty("org.cougaar.core.security.configpoll", "5000");
        waittime = Integer.parseInt(waitPoll);
      } catch (Exception ex) {
        if (log.isWarnEnabled()) {
          log.warn("Unable to parse configpoll property: " + ex.toString());
        }
      }
    }

    public void run() {
      while (true) {

        try {
          Thread.currentThread().sleep(waittime);

          ObjectInputStream ois = new ObjectInputStream(
            new ServletRequestUtil().sendRequest(infoURL, "", waittime));
          // return a trusted policy for this plug to send PKCS request
          // also return a certificate to install in the trusted store
          // the certificate may not be the same as the one specified by
          // the trusted policy, but need to be the upper level signer.
          // for simplicity the root CA certificate will return

          // before the trusted CA starts up completely the CA
          // may return empty, in which case this thread will wait
          // until it gets the right answer.
          if (log.isDebugEnabled()) {
            log.debug("received reply from CA.");
          }

          CAInfo info = (CAInfo)ois.readObject();
          ois.close();

          checkOrMakeIdentity(info, requestURL);

          return;
        } catch (Exception ex) {
          if (ex instanceof IOException) {
            if (log.isDebugEnabled()) {
              log.debug("Waiting to get trusted policy from " + infoURL);
            }
          }
          else {
            if (log.isWarnEnabled()) {
              log.warn("Exception occurred. ", ex);
            }
            return;
          }
        }
      }
    }
  }

  protected void setCAInfo(CAInfo info, String requestURL) {
    TrustedCaPolicy tc = info.caPolicy;
    tc.caURL = requestURL;
    if (cryptoClientPolicy.isCertificateAuthority()) {
      // don't need it for CA, it signs request locally
      tc.setCertificateAttributesPolicy(null);
    }
    cryptoClientPolicy.addTrustedCaPolicy(tc);
    saveTrustedCert(info);
    // there is a TrustedCAConfigPlugin that only installs trusted cert and policy
    if (log.isDebugEnabled()) {
      log.debug("Saving CryptoClientPolicy to file.");
    }
    configParser.updateSecurityPolicy(cryptoClientPolicy);
  }

  protected void saveTrustedCert(CAInfo info) {
    X509Certificate [] certChain = info.caCert;
    // install certificate to trust store
    for (int i = 0; i < certChain.length; i++) {
      X509Certificate c = certChain[i];
      String alias = null;
      X500Name certdn = null;
      try {
        certdn = new X500Name(c.getSubjectDN().getName());

        alias = certdn.getCommonName() + "-1";
      } catch (IOException iox) {
        throw new RuntimeException("Illegal name: " + c);
      }
      // Updating certificate cache
      CertificateStatus cs = cacheservice.addKeyToCache(c, null, alias, CertificateType.CERT_TYPE_CA);
      // Update the certificate trust
      cacheservice.setCertificateTrust(c, cs, certdn, null);

      if (log.isDebugEnabled()) {
        log.debug("Saving trusted cert: " + c + " : alias: " + alias);
      }
      cacheservice.saveCertificateInTrustedKeyStore(c, alias);
    }

  }

  protected synchronized void checkOrMakeIdentity(CAInfo info, String requestURL) {
    // check whether ca policy has been set
    if (configParser.getCaPolicy(caDN) == null) {
      // Build a hashtable of (attribute, value) pairs to replace
      // attributes with their value in a template XML file.
      Hashtable attributeTable = new Hashtable();
      attributeTable.put("distinguishedName", caDN);
      attributeTable.put("ldapURL", ldapURL);

      // other attributes should be static for unzip & run

      PolicyHandler ph = new PolicyHandler(configParser, _sb);
      // retrieve caPolicyTemplate and add new information
      // there should be a CaPolicy created with this function
      // and storage should be updated with new CaPolicy
      ph.addCaPolicy(attributeTable);
    }

    if (cryptoClientPolicy.isRootCA()) {
      if (log.isDebugEnabled()) {
        log.debug("Saving CryptoClientPolicy to file.");
      }
      configParser.updateSecurityPolicy(cryptoClientPolicy);
    }
    else {
      setCAInfo(info, requestURL);
    }

    generateCAIdentity();

    if (log.isDebugEnabled()) {
      log.debug("CA created, now creating node cert.");
    }

    // get node and agent cert
    // done in DirectoryKeyStore
    keyRingService.checkOrMakeCert(NodeInfo.getNodeName());
  }

  private void generateCAIdentity() {
    // handle KeyRing and DirectoryKeyStore which have already initialized
    // with the default parameter (is not CA)

    if (caDN == null || ldapURL == null) {
      log.warn("Cannot auto start CA, DN or LDAP has not been set.");
      return;

      /*
      caDN = "CN=NCA_CA, OU=CONUS, O=DLA, L=San Francisco, ST=CA, C=US, T=ca";
      ldapURL = "ldap://yew:389/dc=rliao1,dc=cougaar,dc=org";
      */
    }

    // check whether CA key already created
    /*
    This code seems useless
    try {
      X500Name dname = new X500Name(caDN);
    }
    catch (IOException e) {
      System.out.println("Unable to create CA certificate: " + e);
      e.printStackTrace();
      return;
    }
    */

    // start generate CA key
    X500Principal p = new X500Principal(caDN);
    AgentIdentityService agentIdentity = (AgentIdentityService)
      _sb.getService(new CAIdentityClientImpl(p),
					    AgentIdentityService.class,
					    null);
    try {
      agentIdentity.acquire(null);
    }
    catch (Exception e) {
      log.warn("Unable to generate CA key: ", e);
      return;
    }

  }

  protected void setupSubscriptions() {
  }

}
