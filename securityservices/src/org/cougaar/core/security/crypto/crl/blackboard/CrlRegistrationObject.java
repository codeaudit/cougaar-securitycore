/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
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
