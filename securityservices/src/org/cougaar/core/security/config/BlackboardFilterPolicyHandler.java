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
import java.util.HashSet;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

// Cougaar security services
import org.cougaar.core.security.policy.*;
import org.cougaar.core.security.util.*;

public class BlackboardFilterPolicyHandler extends BaseConfigHandler {
  private BlackboardFilterPolicy _policy;

  // for read-only rules
  private String    _default;
  private HashSet   _patterns;
  private HashSet   _writeRoles;
  private HashSet   _readRoles;
  private HashSet   _deniedRoles;

  // for select rules
  private HashSet   _methods;
  private HashSet   _allowedRoles;

  // for both
  private String    _agent;
  private boolean   _readOnly;

  public BlackboardFilterPolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String role,
			    String topLevelTag) {
    
    _policy = new BlackboardFilterPolicy();
    currentSecurityPolicy = _policy;
    super.collectPolicy(parser, parent, role, topLevelTag);
  }
  
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attrs )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attrs);
    if (localName.equals("read-only-policy")) {
      _readOnly = true;
    } else if (localName.equals("select-method-policy")) {
      _readOnly = false;
    } else if (localName.equals("rule")) {
      _agent       = attrs.getValue("agent");
      _patterns    = new HashSet();

      if (_readOnly) {
        _default     = null;
        _writeRoles  = new HashSet();
        _readRoles   = new HashSet();
        _deniedRoles = new HashSet();
      } else {
        _allowedRoles = new HashSet();
        _methods      = new HashSet();
      }
    } 
  }
  
  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    super.endElement(namespaceURI, localName, qName);
    if (endElementAction == SKIP) {
      return;
    }
    if (localName.equals("rule")) {
      if (_agent == null) {
        log.error("You must provide an agent name as a rule parameter");
      } else if (_patterns.size() == 0) {
        log.error("You must have at least one uri pattern in a rule");
      } else {
        if (_readOnly) {
          if (_default == null) {
            log.error("You must have a default privilege");
          } else {
            if (BlackboardFilterPolicy.READ_ACCESS.equals(_default)) {
              _default = BlackboardFilterPolicy.READ_ACCESS;
            } else if (BlackboardFilterPolicy.WRITE_ACCESS.equals(_default)) {
              _default = BlackboardFilterPolicy.WRITE_ACCESS;
            } else if (BlackboardFilterPolicy.DENIED_ACCESS.equals(_default)) {
              _default = BlackboardFilterPolicy.DENIED_ACCESS;
            } else {
              log.error("The default privilege must be one of 'read'," + 
                        " 'write', or 'denied'");
              return;
            }
            // good rule
            BlackboardFilterPolicy.ReadOnlyRule rule = createRORule();
            _policy.addReadOnlyRule(rule);
          }
        } else { // select rule
          if (_allowedRoles.size() == 0) {
            log.error("You must have at least one role allowed access to this rule");
          } else if (_methods.size() == 0) {
            log.error("You must have at least one method protected by this rule");
          } else { // yay! good rule
            BlackboardFilterPolicy.SelectRule rule = createSelectRule();
            _policy.addSelectRule(rule);
          }
        }
      }
    } else if (localName.equals("pattern")) {
      _patterns.add(getContents());
    } else if (localName.equals("default-privilege")) {
      _default = getContents();
    } else if (localName.equals("write-role")) {
      _writeRoles.add(getContents());
    } else if (localName.equals("role")) {
      _allowedRoles.add(getContents());
    } else if (localName.equals("method")) {
      _methods.add(getContents());
    } else if (localName.equals("read-role")) {
      _readRoles.add(getContents());
    } else if (localName.equals("denied-role")) {
      _deniedRoles.add(getContents());
    }
  }

  private  BlackboardFilterPolicy.ReadOnlyRule createRORule() {
    BlackboardFilterPolicy.ReadOnlyRule rule =
      new BlackboardFilterPolicy.ReadOnlyRule();
    rule.agent = _agent;
    rule.defaultAccess = _default;
    rule.patterns = _patterns;
    rule.writeRoles = _writeRoles;
    rule.readRoles = _readRoles;
    rule.deniedRoles = _deniedRoles;
    return rule;
  }

  private  BlackboardFilterPolicy.SelectRule createSelectRule() {
    BlackboardFilterPolicy.SelectRule rule =
      new BlackboardFilterPolicy.SelectRule();
    rule.agent = _agent;
    rule.methods = _methods;
    rule.patterns = _patterns;
    rule.roles    = _allowedRoles;
    return rule;
  }
}
