package org.cougaar.core.security.crypto;

import java.security.cert.X509CRL;
import java.util.Date;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.component.Service;

import org.cougaar.core.security.crypto.ldap.LdapEntry;
import org.cougaar.core.security.services.ldap.*;

public class CertificateDirectoryHandler implements CertDirectoryServiceClient {

  public CertificateDirectoryHandler(CertDirectoryServiceRequestor requestor, ServiceBroker sb) {
  }

  public LdapEntry[] searchByCommonName(String commonName) {
    return new LdapEntry[] {};
  }

  /** Return a list of certificates that satisfy a search filter. */
  public LdapEntry[] searchWithFilter(String filter) {
    return new LdapEntry[] {};
  }

  public X509CRL  getCRL(String  distingushName) {
    return null;
  }

  public String getDirectoryServiceURL() {
    return "";
  }

  public int getDirectoryServiceType() {
    return 0;
  }

  public String getModifiedTimeStamp(String dn) {
    return new Date().toString();
  }
}
