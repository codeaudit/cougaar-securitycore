/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 *
 * Created on September 12, 2001, 10:55 AM
 */

package org.cougaar.core.security.acl.auth;

// Cougaar core services
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.component.ServiceBroker;

import org.apache.catalina.Context;
import org.apache.catalina.core.StandardContext;

import org.cougaar.core.security.acl.auth.DualAuthenticator;
import org.cougaar.core.security.provider.ServletPolicyServiceProvider;

import org.apache.catalina.Valve;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.deploy.SecurityCollection;

public class PolicyEnforcerServletContext 
  extends StandardContext {
  public PolicyEnforcerServletContext() {
    ServletPolicyServiceProvider.setContext(this);
  }

  public void addValve(Valve valve) {
    super.addValve(valve);
    if (valve instanceof DualAuthenticator) {
      DualAuthenticator da = (DualAuthenticator) valve;
      ServletPolicyServiceProvider.setDualAuthenticator(da);
    }
  }
  
  /*
  public void addConstraint(SecurityConstraint sc) {
    log.debug("Adding Security Constraint: ");
    log.debug("  AllRoles:       " + sc.getAllRoles());
    log.debug("  AuthConstraint: " + sc.getAuthConstraint());
    log.debug("  DisplayName:    " + sc.getDisplayName());
    log.debug("  UserConstraint: " + sc.getUserConstraint());
    String roles[] = sc.findAuthRoles();
    for (int j = 0 ; j < roles.length; j++) {
      log.debug("  Role:           " + roles[j]);
    }
    SecurityCollection scn[] = sc.findCollections();
    for (int j = 0 ; j < scn.length; j++) {
      log.debug("  SecurityCollection: ");
      log.debug("    Name:         " + scn[j].getName());
      String[] methods = scn[j].findMethods();
      for (int k = 0; k < methods.length; k++) {
        log.debug("    Method:       " + methods[k]);
      }
      String[] patterns = scn[j].findPatterns();
      for (int k = 0; k < patterns.length; k++) {
        log.debug("    Pattern:      " + patterns[k]);
      }
    }
    super.addConstraint(sc);
  }
  */
}
