package org.cougaar.core.security.crypto;

public class NoKeyAvailableException 
  extends java.security.GeneralSecurityException {
  public NoKeyAvailableException(String message) {
    super(message);
  }
/*
  public NoKeyAvailableException(String message, Exception cause) {
    super(message, cause);
  }
*/
}
