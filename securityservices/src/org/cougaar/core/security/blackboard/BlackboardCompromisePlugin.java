/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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


package org.cougaar.core.security.blackboard;


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.crypto.CertificateCache;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.io.PrintWriter;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import java.security.cert.X509Certificate;

import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;


/**
 * Monitors the Blackboard for Blackboard Compromise. Then sends  a
 * revoke agent message to the CA along with the compromise time to revoke
 * the agents Certificates.
 *
 * @author ttschampel
 */
public class BlackboardCompromisePlugin extends ComponentPlugin {
  private static final String REVOKE_CERT_SERVLET_URI = "/RevokeCertificateServlet";
  private String pluginName = "BlackboardCompromisePlugin";
  private IncrementalSubscription compromiseSubs = null;
  private LoggingService logging = null;
  private UnaryPredicate compromisePredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return o instanceof CompromiseBlackboard;
    }
  };

  KeyRingService keyRingService = null;
  ConfigParserService configParserService = null;

  /**
   * Set Logging Service
   *
   * @param service LoggingService
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;
    this.keyRingService = (KeyRingService) this.getServiceBroker().getService(this, KeyRingService.class, null);
    if (keyRingService == null) {
      if (logging.isErrorEnabled()) {
        logging.error("Error getting key ring service for " + pluginName);
      }
    }

    this.configParserService = (ConfigParserService) this.getServiceBroker().getService(this, ConfigParserService.class, null);
    if (configParserService == null) {
      if (logging.isErrorEnabled()) {
        logging.error("Error getting config parser service for " + pluginName);
      }
    }
  }


  /**
   * setup subscriptions
   */
  public void setupSubscriptions() {
    compromiseSubs = (IncrementalSubscription) this.getBlackboardService().subscribe(compromisePredicate);
  }


  /**
   * Load security services
   */
  public void load() {
    super.load();

  }


  /**
   * Check for Compromise Blackboard Objects
   */
  public void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");
    }

    Enumeration enumeration = compromiseSubs.getAddedList();
    if (enumeration.hasMoreElements()) {
      CompromiseBlackboard cb = (CompromiseBlackboard) enumeration.nextElement();
      long timestamp = cb.getTimestamp();
      if (logging.isWarnEnabled()) {
        logging.warn("Blackboard has been compromised at time " + new Date(timestamp) + ", sending restart");
      }

      revokeAgentCert(timestamp);
    }
  }


  /**
   * Send revoke agent cert message to Ca Agent's RevokeCertificateServlet
   *
   * @param timestamp timestamp of the compromise
   */
  private void revokeAgentCert(long timestamp) {
    String agentName = this.getAgentIdentifier().getAddress();
    if (logging.isDebugEnabled()) {
      logging.debug("Revoking " + agentName + " cert for compromise at:" + new Date(timestamp));
    }

    List certList = keyRingService.findCert(agentName);
    if ((certList == null) || (certList.size() == 0)) {
      if (logging.isWarnEnabled()) {
        logging.warn("no certificate(s) available for: " + agentName);
      }
    } else {
      Iterator certs = certList.iterator();
      String caDN = null;
      String reply = "";

      // for now there should only be one certificate signed by one CA
      while (certs.hasNext()) {
        CertificateStatus status = (CertificateStatus) certs.next();
        X509Certificate cert = status.getCertificate();
        if (logging.isDebugEnabled()) {
          logging.debug("Found certificate dn = " + cert.getSubjectDN().getName());
        }

        X509Certificate[] certChain = keyRingService.findCertChain(cert);
        if (certChain != null) {
          // get the CA's dn from the certificate chain
          caDN = getCADN(certChain);

          if (caDN != null) {
            if (logging.isDebugEnabled()) {
              logging.debug("CA DN: " + caDN);
            }


            // send request to RevokeCertificateServlet
            //reply = sendRevokeCertRequest(agentName, caDN);
            String revokeCertServletURL = null;
            HttpURLConnection huc = null;
            CryptoClientPolicy policy = getCryptoClientPolicy();
            if (policy == null) {
              if (logging.isErrorEnabled()) {
                logging.error("cryptoClientPolicy is null");
              }
            }

            TrustedCaPolicy[] trustedCaPolicy = policy.getTrustedCaPolicy();
            String caURL = trustedCaPolicy[0].caURL;

            // construct the revoke certificate servlet url
            revokeCertServletURL = caURL.substring(0, caURL.lastIndexOf('/')) + REVOKE_CERT_SERVLET_URI;
            if (logging.isDebugEnabled()) {
              logging.debug("Sending revoke certificate request to: " + revokeCertServletURL);
            }

            try {
              URL url = new URL(revokeCertServletURL);
              huc = (HttpURLConnection) url.openConnection();
              // Don't follow redirects automatically.
              huc.setInstanceFollowRedirects(false);
              // Let the system know that we want to do output
              huc.setDoOutput(true);
              // Let the system know that we want to do input
              huc.setDoInput(true);
              // No caching, we want the real thing
              huc.setUseCaches(false);
              // Specify the content type
              huc.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
              huc.setRequestMethod("POST");
              PrintWriter out = new PrintWriter(huc.getOutputStream());
              StringBuffer sb = new StringBuffer();
              sb.append("agent_name=");
              sb.append(URLEncoder.encode(agentName, "UTF-8"));
              sb.append("&revoke_type=agent");
              sb.append("&compromise_time=" + timestamp);
              sb.append("&ca_dn=");
              sb.append(URLEncoder.encode(caDN, "UTF-8"));
              out.println(sb.toString());
              out.flush();
              out.close();
            } catch (Exception e) {
              if (logging.isWarnEnabled()) {
                logging.warn("Unable to send revoke certificate request to CA: " + e);
              }
            }

            if (logging.isDebugEnabled()) {
              logging.debug("Revoke certificate request reply:\n" + reply);
            }
          } else {
            if (logging.isWarnEnabled()) {
              logging.warn("No CA dn(s) where found in certificate chain for: " + agentName);
            }
          }
        } else {
          if (logging.isWarnEnabled()) {
            logging.warn("Can't get certificate chain for cert: " + cert.getSubjectDN().getName());
          }
        }
      }
    }
  }


  private String getCADN(X509Certificate[] certChain) {
    int len = certChain.length;
    String title = null;
    String dn = null;

    for (int i = 0; i < len; i++) {
      dn = certChain[i].getIssuerDN().getName();
      title = CertificateUtility.findAttribute(dn, "t");
      if (title.equals(CertificateCache.CERT_TITLE_CA)) {
        return dn;
      }
    }

    return null;
  }


  private CryptoClientPolicy getCryptoClientPolicy() {
    CryptoClientPolicy cryptoClientPolicy = null;
    try {
      SecurityPolicy[] sp = configParserService.getSecurityPolicies(CryptoClientPolicy.class);
      cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    } catch (Exception e) {
      if (logging.isErrorEnabled()) {
        logging.error("Can't obtain client crypto policy : " + e.getMessage());
      }
    }

    return cryptoClientPolicy;
  }
}
