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

package org.cougaar.core.security.crypto;

import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.security.cert.*;

public class CRLKey 
{
  BigInteger SerialNumber=null;
  String IssuerDN=null;
  private int hash=0;
  public CRLKey(BigInteger serialno, String issuer)
  {
    this.SerialNumber=serialno;
    this.IssuerDN=issuer;
  }
  public boolean equals (Object object) {
    boolean equal=false;

    CRLKey crlobject=null;
    if(!(object instanceof CRLKey)) 
      return false;
      crlobject=(CRLKey)object;
      if((this.SerialNumber.equals(crlobject.SerialNumber))&&(this.IssuerDN.equals(crlobject.IssuerDN))) {
	equal=true;
      }

    return equal;
  }
  public String toString()
  {
    StringBuffer buffer=new StringBuffer();
    buffer.append("Serial no : "+SerialNumber.toString()+"\n");
    buffer.append("Issuer dn : "+IssuerDN+"\n");
    return buffer.toString();
  }
  public int hashCode() {
     int i = hash;
     if(i == 0)  {
       i=this.SerialNumber.hashCode();
       hash = i;
     }
     return i;
  }
     
  
}
