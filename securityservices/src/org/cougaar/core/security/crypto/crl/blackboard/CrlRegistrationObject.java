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


package org.cougaar.core.security.crypto.crl.blackboard;


import org.cougaar.core.blackboard.Publishable;
import org.cougaar.core.mts.MessageAddress;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Enumeration;
import java.util.Vector;

public class CrlRegistrationObject implements Serializable,Publishable {

  private Vector messageAddress;
  public String ldapUrl;
  public int ldapType;
  private byte[] derEncodedCrl;
  private String modifiedTimestamp;
  public String dnName;

  public CrlRegistrationObject (String dnname) {
     dnName=dnname;
    ldapUrl=null;
    ldapType=-1;
    modifiedTimestamp=null;
    messageAddress=new Vector();
  }
  
  public CrlRegistrationObject (String dnname,String ldapURL,int ldaptype) {
    dnName=dnname;
    ldapUrl=ldapURL;
    ldapType=ldaptype;
    modifiedTimestamp=null;
    messageAddress=new Vector();
  }

  public void addAgent(MessageAddress agentAddress) throws CRLAgentRegistrationException{
    
    if(agentAddress!=null) {
      MessageAddress msgAddress=null;
      Enumeration enum =messageAddress.elements();
      while(enum.hasMoreElements()) {
        msgAddress=(MessageAddress)enum.nextElement();
        if(msgAddress.toString().equals(agentAddress.toString())) {
          throw new CRLAgentRegistrationException(" Agent " +agentAddress.toString()+
						  "alredy registered");
        }
      }
      messageAddress.add(agentAddress);
    }
  }
  
  public void removeAgent(String agentAddress) throws CRLAgentRegistrationException{
     if(agentAddress!=null) {
      MessageAddress msgAddress=null;
      Enumeration enum =messageAddress.elements();
      while(enum.hasMoreElements()) {
        msgAddress=(MessageAddress)enum.nextElement();
        if(msgAddress.toString().equals(agentAddress)) {
          messageAddress.remove(msgAddress);
          break;
        }
      }
     }
     else {
       throw new CRLAgentRegistrationException(" No  Agent are registered yet " );
     }
  }

  public void setModifiedTime(String modifiedTime){
    modifiedTimestamp=modifiedTime;
  }

  public void setCRL(byte[] encodedCrl) {
    derEncodedCrl=encodedCrl;
  }

  public X509CRL  getCRL() {
    X509CRL crl =null;
    if(derEncodedCrl!=null){
      try {
        InputStream inStream = new ByteArrayInputStream(derEncodedCrl);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        crl = (X509CRL)cf.generateCRL(inStream);
        inStream.close();
      }
      catch (Exception exp){
        return crl;
      }
    }
    return crl;
  }
  public String getModifiedTimeStamp() {
    return modifiedTimestamp;
  }

  public Vector getRegisteredAgents() {
    return messageAddress;
  }

  public boolean isPersistable() {
    return true;
  }

  public String toString(){
    StringBuffer buffer=new StringBuffer();
    if(ldapUrl!=null) {
      buffer.append("ldap URL :"+ldapUrl+"\n");
    }
    buffer.append("ldap type :"+ldapType+"\n");
    if(dnName!=null){
      buffer.append("DN Name :"+dnName+"\n");
    }
    if(modifiedTimestamp!=null){
      buffer.append("Modified time stamp :"+modifiedTimestamp+"\n");
    }
    if(!messageAddress.isEmpty()) {
      buffer.append("Registered Addressers are  :"+"\n");
      MessageAddress msgAddress=null;
      for(int i=0;i<messageAddress.size();i++) {
        msgAddress=(MessageAddress)messageAddress.elementAt(i);
	buffer.append(msgAddress.toString()+"\n");
      }
    }
    return buffer.toString();

  }


}
