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

import java.io.Serializable;

import org.cougaar.core.blackboard.Publishable;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class CRLAgentRegistration implements Serializable,Publishable{
  public  String dnName;
  public String ldapURL;
  public int ldapType;
  private boolean registration ;

  public CRLAgentRegistration(String dnname) {
    dnName=dnname;
    ldapURL=null;
    ldapType=-1;
    registration =true;
  }
  
  public CRLAgentRegistration(String dnname, String ldapurl,int ldaptype, boolean register){
    dnName=dnname;
    ldapURL=ldapurl;
    ldapType=ldaptype;
    registration = register;
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
    if(ldapType>-1){
      buffer.append("ldapType="+ldapType+"\n");
    }
    if(registration){
      buffer.append("to register= True \n");
    }
    else{
      buffer.append("to register= False \n");
    }
    return buffer.toString();
  }
  
  public boolean toRegister(){
    return registration;
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
