/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
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
