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

import java.io.Serializable;
import org.cougaar.core.blackboard.Publishable;

import org.w3c.dom.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.apache.xml.serialize.*;

public class CRLAgentRegistration implements Serializable,Publishable{
  public  String dnName;
  public String ldapURL;
  public int ldapType;
  
  public CRLAgentRegistration(String dnname, String ldapurl,int ldaptype){
    dnName=dnname;
    ldapURL=ldapurl;
    ldapType=ldaptype;
  }
  public boolean isPersistable() {
    return true;
  }
  
  public String toString() {
    StringBuffer buffer=new StringBuffer();
    if(dnName!=null) {
      buffer.append("dn="+dnName+"\n");
    }
    if(ldapURL!=null){
      buffer.append("ldapurl="+ldapURL+"\n");
    }
    buffer.append("ldapType="+ldapType+"\n");
    return buffer.toString();
  }

  public Node convertToXML(Document parent){
    // Element agentregNode = parent.createElement("CRLAgentRegistration");
    if(dnName!=null) {
       Node dnNameNode = parent.createElement("DN");
       dnNameNode.appendChild(parent.createTextNode(dnName));
       parent.appendChild(dnNameNode);
    }
    if(ldapURL!=null) {
       Node ldapURLNode = parent.createElement("LDAP URL");
       ldapURLNode.appendChild(parent.createTextNode(ldapURL));
       parent.appendChild(ldapURLNode);
    }
    Node ldapTypeNode = parent.createElement("LDAP TYPE");
    ldapTypeNode.appendChild(parent.createTextNode(new StringBuffer().append(ldapType).toString()));
    parent.appendChild(ldapTypeNode);
    
    return parent;

  }


}
