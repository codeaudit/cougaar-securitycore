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


package org.cougaar.core.security.config;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.LdapUserServicePolicy;

import java.util.ArrayList;
import java.util.List;

import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

public class LdapUserServicePolicyHandler extends BaseConfigHandler {
  private LdapUserServicePolicy _policy;

  private List _userObjectClass = new ArrayList();
  private List _roleObjectClass = new ArrayList();

  public LdapUserServicePolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {
    
    _policy = new LdapUserServicePolicy();
    currentSecurityPolicy = _policy;
    super.collectPolicy(parser, parent, topLevelTag);
  }
  
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attrs )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attrs);
  }
  
  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    super.endElement(namespaceURI, localName, qName);
    if (endElementAction == SKIP) {
      return;
    }

    if (localName.equals("ldap-url")) {
      _policy.ldapUrl = getContents();
    } else if (localName.equals("ldap-user")) {
      _policy.ldapUser = getContents();
    } else if (localName.equals("ldap-password")) {
      _policy.ldapPassword = getContents();
    } else if (localName.equals("user-dn")) {
      _policy.userDN = getContents();
    } else if (localName.equals("role-dn")) {
      _policy.roleDN = getContents();
    } else if (localName.equals("user-attr")) {
      _policy.userRDN = getContents();
    } else if (localName.equals("role-attr")) {
      _policy.roleRDN = getContents();
    } else if (localName.equals("user-object-class")) {
      _userObjectClass.add(getContents());
      _policy.userObjectClass = (String[])
        _userObjectClass.toArray(new String[_userObjectClass.size()]);
    } else if (localName.equals("role-object-class")) {
      _roleObjectClass.add(getContents());
      _policy.roleObjectClass = (String[])
        _roleObjectClass.toArray(new String[_roleObjectClass.size()]);
    } else if (localName.equals("user-role-attr")) {
      _policy.roleAttr = getContents();
    } else if (localName.equals("auth-attr")) {
      _policy.authAttr = getContents();
    } else if (localName.equals("enable-attr")) {
      _policy.enableAttr = getContents();
    } else if (localName.equals("password-attr")) {
      _policy.passwordAttr = getContents();
    } else if (localName.equals("cert-special-attr")) {
      _policy.certOkAttr = getContents();
    }
    writerReset();
  }
}
