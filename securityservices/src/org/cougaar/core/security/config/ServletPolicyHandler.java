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

import java.util.ArrayList;
import java.util.List;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.security.policy.ServletPolicy;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

public class ServletPolicyHandler extends BaseConfigHandler {
  private ServletPolicy _policy;

  private String        _agent;
  private List          _roles;
  private String        _authType;
  private List          _patterns;
  private boolean       _requireSSL;
  
  public ServletPolicyHandler(ServiceBroker sb) {
    super(sb);
  }
  
  public void collectPolicy(XMLReader parser,
			    ContentHandler parent,
			    String topLevelTag) {
    
    _policy = new ServletPolicy();
    currentSecurityPolicy = _policy;
    super.collectPolicy(parser, parent, topLevelTag);
  }
  
  public void startElement( String namespaceURI,
			    String localName,
			    String qName,
			    Attributes attrs )
    throws SAXException {
    super.startElement(namespaceURI, localName, qName, attrs);

    if (localName.equals("root")) {
      _agent    = null;
      _roles    = null;
      _authType = null;
    } else if (localName.equals("agent")) {
      _agent    = attrs.getValue("name");
      _patterns = null;
      _roles    = null;
      _authType = null;
    } else if (localName.equals("rule")) {
      _patterns = new ArrayList();
      _roles    = new ArrayList();
      _authType = null;
      String requireSSL = attrs.getValue("requireSSL");
      _requireSSL = false;
      if ("yes".equalsIgnoreCase(requireSSL) ||
          "true".equalsIgnoreCase(requireSSL) ||
          "1".equals(requireSSL)) {
        _requireSSL = true;
      }
      _authType = attrs.getValue("auth");
      if (_authType == null) {
        _authType = "EITHER";
      } else if ("CERT".equalsIgnoreCase(_authType) ||
                 "EITHER".equalsIgnoreCase(_authType) ||
                 "PASSWORD".equalsIgnoreCase(_authType)) {
        _authType = _authType.toUpperCase();
      } else {
        log.error("Invalid auth type: '" + _authType +
                    "' expecting EITHER, PASSWORD, or CERT");
        _authType = "EITHER";
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

    if (localName.equals("role")) {
      _roles.add(getContents());
    } else if (localName.equals("pattern")) {
      _patterns.add(getContents());
    } else if (localName.equals("agent")) {
      // already added it in the end rule
      _agent = null;
    } else if (localName.equals("root")) {
      // don't need to do anything
    } else if (localName.equals("rule")) {
      if (_patterns.size() == 0 || _roles.size() == 0) {
        log.error("Rules must have at least one pattern and " +
                  "at least one role. Skipping this one");
      } else {
        if (_agent == null) {
          _policy.addRootRule(_patterns, _authType, _roles, _requireSSL);
        } else {
          _policy.addRule(_agent, _patterns, _authType, _roles, _requireSSL);
        }
        _roles    = null;
        _authType = null;
        _patterns = null;
      }
    } else if (localName.equals("failure-delay")) {
      try {
        _policy.setFailureDelay(Long.parseLong(getContents()));
      } catch (NumberFormatException e) {
        log.error("The failure-delay element must contain a long integer");
      }
    } else if (localName.equals("session-life")) {
      try {
        _policy.setSessionLife(Long.parseLong(getContents()));
      } catch (NumberFormatException e) {
        log.error("The failure-delay element must contain a long integer");
      }
    }
    writerReset();
  }
}
