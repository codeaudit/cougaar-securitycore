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

import java.util.Collection;
import java.util.HashSet;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.BlackboardFilterPolicy;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

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

  public BlackboardFilterPolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {
    
    _policy = new BlackboardFilterPolicy();
    currentSecurityPolicy = _policy;
    super.collectPolicy(parser, parent, topLevelTag);
  }
  
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attrs )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attrs);
    if (localName.equals("read-only-rule")) {
      _agent       = attrs.getValue("agent");
      _default     = attrs.getValue("default-privilege",
                                    BlackboardFilterPolicy.DENIED_ACCESS);
      _patterns    = new HashSet();
      _writeRoles  = new HashSet();
      _readRoles   = new HashSet();
      _deniedRoles = new HashSet();
    } else if (localName.equals("select-method-rule")) {
      _agent        = attrs.getValue("agent");
      _patterns     = new HashSet();
      _allowedRoles = new HashSet();
      _methods      = new HashSet();
    } 
  }

  private boolean checkAgent() {
    if (_agent == null) {
      log.error("You must provide an agent name as a rule parameter");
      return false;
    }
    return true;
  }

  private boolean checkSize(Collection coll, String name) {
    if (coll == null || coll.size() == 0) {
      log.error("You must provide at least one " + name + " element");
      return false;
    }
    return true;
  }
  
  private boolean checkDefaultAccess() {
    if (BlackboardFilterPolicy.READ_ACCESS.equals(_default)) {
      _default = BlackboardFilterPolicy.READ_ACCESS;
    } else if (BlackboardFilterPolicy.WRITE_ACCESS.equals(_default)) {
      _default = BlackboardFilterPolicy.WRITE_ACCESS;
    } else if (BlackboardFilterPolicy.DENIED_ACCESS.equals(_default)) {
      _default = BlackboardFilterPolicy.DENIED_ACCESS;
    } else {
      log.error("The default privilege must be one of 'read'," + 
                " 'write', or 'denied'");
      return false;
    }
    return true;
  }

  public void endElement( String namespaceURI,
			  String localName,
			  String qName )
    throws SAXException {
    super.endElement(namespaceURI, localName, qName);
    if (endElementAction == SKIP) {
      return;
    }
    if (localName.equals("read-only-rule")) {
      if (checkAgent() && 
          checkSize(_patterns, "pattern") &&
          checkDefaultAccess()) {
        // good rule
        BlackboardFilterPolicy.ReadOnlyRule rule = createRORule();
        _policy.addReadOnlyRule(rule);
      }
    } else if (localName.equals("select-method-rule")) {
      if (checkAgent() &&
          checkSize(_allowedRoles, "role") &&
          checkSize(_methods,"method") &&
          checkSize(_patterns,"pattern")) {
        BlackboardFilterPolicy.SelectRule rule = createSelectRule();
        _policy.addSelectRule(rule);
      }
    } else if (localName.equals("pattern")) {
      _patterns.add(getContents());
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
    writerReset();
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
