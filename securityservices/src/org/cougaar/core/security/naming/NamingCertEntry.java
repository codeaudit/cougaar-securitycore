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


package org.cougaar.core.security.naming;

import org.cougaar.core.service.wp.Cert;

import java.util.List;
import java.util.Iterator;

final public class NamingCertEntry extends Cert
{
  /**
   * Should store one cert per signer, however it is not enforced,
   * it is up to the retrieve function to digest all the cert paths.
   * It is also up to the retrieve function to verify cert validity.
   */
  //Hashtable certList = new Hashtable();
  /*
  ArrayList certList = new ArrayList();
  ArrayList dnList = new ArrayList();
  CertificateType certType = CertificateType.CERT_TYPE_END_ENTITY;
  */
  List certList;
  List dnList;

  /*
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
  */

  // make white page entry immutable
  public NamingCertEntry(List dnlist, List certlist) {
    if (dnlist == null || certlist == null)
      throw new RuntimeException("DN or Cert list is NULL");

    dnList = dnlist;
    certList = certlist;

    _hashcode = 0;
    for (int i = 0; i < dnlist.size(); i++) {
      _hashcode += ((String)dnlist.get(i)).hashCode();
    }
    // should not need to hash the certificate, there should not
    // be more than one entry at any time
    for (int i = 0; i < certlist.size(); i++) {
      _hashcode += certlist.get(i).toString().hashCode();
    }
  }

  final public List getEntries() {
    return certList;
  }

  final public List getDNList() {
    return dnList;
  }

  public boolean equals(Object o) {
    if (o instanceof NamingCertEntry) {
      return (((NamingCertEntry)o).hashCode() == hashCode());
    }

    return false;
  }

  public int hashCode() {
    return _hashcode;
  }

  int _hashcode;
  public String toString() {
    StringBuffer buff=new StringBuffer();
    if(certList.isEmpty()) {
      buff.append("CertList is empty");
    }
    Iterator iter =certList.iterator();
    Object Obj=null;
    CACertificateEntry caentry =null;
    CertificateEntry certentry =null;
    while(iter.hasNext()){
      Obj=(Object)iter.next();
      if(Obj instanceof CACertificateEntry) {
        caentry=(CACertificateEntry)Obj;
        buff.append (" CA Entry  : "+ caentry.toString() +"\n");
      }
      if(Obj instanceof CertificateEntry) {
       certentry=(CertificateEntry)Obj;
        buff.append (" Certificate Entry  : "+ certentry.toString() +"\n"); 
      }
    }
    return buff.toString();
  }
}
