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

import java.math.BigInteger;

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
