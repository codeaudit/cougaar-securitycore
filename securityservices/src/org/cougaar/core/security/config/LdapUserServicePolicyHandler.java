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
 * Created on May 28, 2002, 5:48 PM
 */

package org.cougaar.core.security.config;

import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

public class LdapUserServicePolicyHandler extends BaseConfigHandler {
  private LdapUserServicePolicy _policy;

  private List _userObjectClass = new ArrayList();
  private List _roleObjectClass = new ArrayList();

  public LdapUserServicePolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String role,
			    String topLevelTag) {
    
    _policy = new LdapUserServicePolicy();
    currentSecurityPolicy = _policy;
    super.collectPolicy(parser, parent, role, topLevelTag);
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
    } else if (localName.equals("user-rdn")) {
      _policy.userRDN = getContents();
    } else if (localName.equals("role-rdn")) {
      _policy.roleRDN = getContents();
    } else if (localName.equals("user-object-class")) {
      _userObjectClass.add(getContents());
      _policy.userObjectClass = (String[])
        _userObjectClass.toArray(new String[_userObjectClass.size()]);
    } else if (localName.equals("role-object-class")) {
      _roleObjectClass.add(getContents());
      _policy.roleObjectClass = (String[])
        _roleObjectClass.toArray(new String[_roleObjectClass.size()]);
    } else if (localName.equals("role-attribute")) {
      _policy.roleAttr = getContents();
    } else if (localName.equals("auth-attribute")) {
      _policy.authAttr = getContents();
    } else if (localName.equals("enable-attribute")) {
      _policy.enableAttr = getContents();
    } else if (localName.equals("password-attribute")) {
      _policy.passwordAttr = getContents();
    }
  }
}
