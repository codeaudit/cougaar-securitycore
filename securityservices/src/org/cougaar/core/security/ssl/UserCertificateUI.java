package org.cougaar.core.security.ssl;

public interface UserCertificateUI {
  public String chooseClientAlias(String serveralias,
                            String serverhost,
                            String serverport);

}