package org.cougaar.core.security.crypto;

import org.cougaar.core.security.certauthority.ConfigPlugin;
import org.cougaar.core.security.certauthority.servlet.CAInfo;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.util.NodeInfo;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import sun.security.x509.X500Name;

public class AutoConfigPlugin extends ConfigPlugin {
  Vector calist = new Vector();

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() == 0) {
      System.out.println("No CA assigned!");
    }
    Iterator it = l.iterator();
    while (it.hasNext()) {
      String param = (String)it.next();
      //log.debug("Unzip & run CA: " + param);
      calist.addElement(param);
    }

  }

  protected void execute() {
    for (int i = 0; i < calist.size(); i++) {
      addTrustedPolicy((String)calist.elementAt(i), (i == 0));
    }
  }

  /** Need to synchronize because for normal node there could be multiple threads
   *  changing cryptoClientPolicy as well as requesting certificates
   */
  protected synchronized void checkOrMakeIdentity(CAInfo info, String requestURL) {
    // check whether already received the policy
    TrustedCaPolicy [] tc = cryptoClientPolicy.getIssuerPolicy();
    boolean newPolicy = true;
    for (int i = 0; i < tc.length; i++) {
      if (tc[i].caDN.equals(info.caPolicy.caDN)) {
        newPolicy = false;
        break;
      }
    }
    if (newPolicy) {
      setCAInfo(info, requestURL);
    }
    TrustedCaPolicy tcp = info.caPolicy;

    // request certificates from the particular CA that has started
    // the certificate may have been created
    if (log.isDebugEnabled()) {
      log.debug("CA " + info.caPolicy.caDN + " started, sending requests.");
    }
    X500Name dname = null;
    try {
      String nodename = NodeInfo.getNodeName();
      dname = new X500Name(CertificateUtility.getX500DN(nodename,
        CertificateCache.CERT_TITLE_NODE,
        tcp.getCertificateAttributesPolicy()));
    } catch (IOException iox) {}

    keyRingService.checkOrMakeCert(dname, false, tcp);
  }
}
