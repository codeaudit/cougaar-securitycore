package org.cougaar.core.security.crypto;

import org.cougaar.core.security.certauthority.ConfigPlugin;
import org.cougaar.core.security.certauthority.servlet.CAInfo;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.certauthority.servlet.CAInfo;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;

/*
 * This class only add trusted policy and trusted CA certificate,
 * it does not request certificate from the CA, this is used for 
 * multiple root CA so that their subordinate CAs can trust each other.
 */

public class TrustedCAConfigPlugin extends ConfigPlugin {
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
      calist.addElement(param);
    }

  }

  protected void execute() {
    if (log.isDebugEnabled()) {
      log.debug("executing ... ");
    }
    for (int i = 0; i < calist.size(); i++) {
      addTrustedPolicy((String)calist.elementAt(i), true);
    }
  }

  /** Need to synchronize because for normal node there could be multiple threads
   */
  protected synchronized void checkOrMakeIdentity(CAInfo info, String requestURL) {
  }

}
