/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.naming;

import java.util.*;
import java.security.cert.*;
import java.security.*;
import sun.security.x509.*;

import org.cougaar.core.service.wp.*;

import org.cougaar.core.security.crypto.*;

final public class NamingCertEntry extends Cert
{
  /**
   * Should store one cert per signer, however it is not enforced,
   * it is up to the retrieve function to digest all the cert paths.
   * It is also up to the retrieve function to verify cert validity.
   */
  //Hashtable certList = new Hashtable();
  ArrayList certList = new ArrayList();
  ArrayList dnList = new ArrayList();
  CertificateType certType = CertificateType.CERT_TYPE_END_ENTITY;

  public void addEntry(String dname, CertificateEntry certEntry, boolean overwrite) {
    if (!dnList.contains(dname)) {
      dnList.add(dname);
    }
    PublicKey pubKey = certEntry.getCertificate().getPublicKey();
    for (int i = 0; i < certList.size(); i++) {
      CertificateEntry acertEntry = (CertificateEntry)certList.get(i);
      if (acertEntry.getCertificate().getPublicKey().equals(pubKey)) {
        // duplicate entry
        if (overwrite) {
          certList.set(i, certEntry);
        }
        return;
      }
    }
    certList.add(certEntry);
  }

  public List getEntries() {
    return certList;
  }

  public List getDNList() {
    return dnList;
  }
}
