/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 *
 * Created on September 12, 2001, 10:55 AM
 */


package org.cougaar.core.security.crypto;

public class CertificateTrust {
  // enumerator name
  private final String enum_name;

  // private constructor, called only within this class
  private CertificateTrust(String name) {
    enum_name = name;
  }

  // return the enumerator name
  public String toString() {
    return enum_name;
  }

  // Certificate status not known yet. Certificate should not be used.
  public static final CertificateTrust CERT_TRUST_UNKNOWN =
    new CertificateTrust("TRUST_UNKNOWN");

  // The certificate has been self issued but the CA reply has
  // not been received yet. The certificate should not be used
  // until a CA reply has been received.
  public static final CertificateTrust CERT_TRUST_SELF_SIGNED =
    new CertificateTrust("TRUST_SELF_SIGNED");

  /** The certificate is signed by a trusted CA
   * Note that a certificate may have been signed by a CA, but it may
   * not be valid because it is not yet valid.
   * One of the certificates in the chain may not be valid either. */
  public static final CertificateTrust CERT_TRUST_CA_SIGNED =
    new CertificateTrust("TRUST_CA_SIGNED");

  // The certificate is not signed by a trusted CA
  // (and should not be used).
  // One possible reason is when the certificate has expired.
  public static final CertificateTrust CERT_TRUST_NOT_TRUSTED =
    new CertificateTrust("TRUST_NOT_TRUSTED");

  // The certificate is a trusted CA certificate
  public static final CertificateTrust CERT_TRUST_CA_CERT =
    new CertificateTrust("TRUST_CA_CERT");

  // The certificate is a revoked certificate
   public static final CertificateTrust CERT_TRUST_REVOKED_CERT =
    new CertificateTrust("TRUST_REVOKED_CERT");

}
