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

public class CertificateOrigin {
  // enumerator name
  private final String enum_name;

  // private constructor, called only within this class
  private CertificateOrigin(String name) {
    enum_name = name;
  }

  // return the enumerator name
  public String toString() {
    return enum_name;
  }

  // The certificate is in a local keystore
  public static final CertificateOrigin CERT_ORI_KEYSTORE =
    new CertificateOrigin("ORI_KEYSTORE");

  // The certificate was retrieved from an LDAP directory
  public static final CertificateOrigin CERT_ORI_LDAP =
    new CertificateOrigin("ORI_LDAP");

  // The certificate was retrieved during an SSL handshake
  public static final CertificateOrigin CERT_ORI_SSL =
    new CertificateOrigin("ORI_SSL");

  // The certificate was received from a Cougaar message (in a PKCS#12
  // envelope).
  public static final CertificateOrigin CERT_ORI_PKCS12 =
    new CertificateOrigin("ORI_PKCS12");
}
