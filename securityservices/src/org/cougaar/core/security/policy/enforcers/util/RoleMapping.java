/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;



/**
 * The purpose of this class is to facilitate the mapping between DAML
 * concepts and the UltraLog concepts.  For now I am using
 * configuration files but some of this will change later...
 */
public class RoleMapping {

  private Map            _componentMap;
  private Map            _agentMap;
  private Map            _uriMap;
  private ServiceBroker  _sb;
  private LoggingService _log;

  public RoleMapping(ServiceBroker sb)
  {
    _sb = sb;
    _log = (LoggingService) _sb.getService(this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing Role Mapper");
    }

    initializeComponent();
    initializeAgent();
    initializeUri();
  }


  private void initializeComponent() {
    try {
      _log.debug("loading component/role mappings...");
      _componentMap = (new StringPairMapping(_sb, "OwlMapRoleComponent")).buildMap();
    } catch (IOException e) {
      _log.error("IOException reading coponent -> role configuration file", e);
    }
  }

  private void initializeAgent() {
    try {
      _log.debug("loading agent/role mappings...");
      _agentMap = (new StringPairMapping(_sb, "OwlMapRoleAgent")).buildMap();
    } catch (IOException e) {
      _log.error("IOException reading agent -> role configuration file", e);
    }
  }

  private void initializeUri() {
    try {
      _log.debug("loading uri/role mappings...");
      _uriMap = (new StringPairMapping(_sb, "OwlMapRoleUri")).buildMap();
    } catch (IOException e) {
      _log.error("IOException reading uri -> role configuration file", e);
    }
  }

  public Set getRolesForComponent(String className) {
    int index = className.length();
    int jndex;
    HashSet roles = new HashSet();
    while (index != -1) {
      className = className.substring(0, index);
      Set s = (Set) _componentMap.get(className);
      if (s != null) {
        roles.addAll(s);
      }
      index = className.lastIndexOf('.');
      jndex = className.lastIndexOf('$');
      if (jndex > index) {
        index = jndex;
      }
    }
    return roles;
  }

  public Set getRolesForAgent(String agent) {
    Set roles = (Set) _agentMap.get(agent);
    if (roles == null) {
      return new HashSet();
    }
    return new HashSet(roles); // need to clone so they can't change it?
  }
  
  // @ param uri formatted as "/$<agent-name>/<path>"
  // matching uri format strings could ONLY be one of the 4:
  //  /$*/*
  //  /$*/<path>
  //  /$<agent-name>/*
  //  /$<agent-name>/<path>
  //
  // @return the union of all the matched set of roles
  // NOTE: the path can either be a '*' or the full path.
  //       for example, this is an invalid pattern:
  //       /$NCA/alpha/* or "/$NCA/*/tasks".
  public Set getRolesForUri(String uri) {
    int index;
    boolean first = true;
    String agent = null;
    // the union of all the roles where the pattern matches the uri
    Set roles = new HashSet();
    
    // get most specific mapping "/$<agent-name>/<path>"
    Set s = (Set)_uriMap.get(uri);
    getUnion(roles, (Set)s);

    // break "/$<agent-name>/<path>" in "/$<agent-name>" and "/<path>"
    if (uri.startsWith("/$")) {
      index = uri.indexOf('/',2);
      if (index == -1) {
        agent = uri;
        uri = "/";
      } else {
        agent = uri.substring(0, index-1);
        uri = uri.substring(index);
      }
    }
    // else we should throw an exception since the format of the uri is not 
    // what we expected.    
    if(agent != null) {
      // get "/$<agent-name>/*"
      s = (Set)_uriMap.get(agent + "/*");
      getUnion(roles, (Set)s);
      // get "/$*/<path>"
      s = (Set)_uriMap.get("/$*" + uri);
      getUnion(roles, (Set)s);
      // get "/$*/*"
      s = (Set)_uriMap.get("/$*/*");
      getUnion(roles, (Set)s);
    }
    return roles;
  }
  
  private void getUnion(Set s1, Set s2) {
    
    if(s2 != null) {
      s1.addAll(s2); 
    }
  }
  
  /*
  private void printSet(Set s, String setname) {
    Iterator i = s.iterator();
    System.out.println("##### BEGIN Printing set " + setname + " #####");
    while(i.hasNext()) {
      System.out.println("" + i.next()); 
    }
    System.out.println("##### END Printing set #####"); 
  }
  */
}
