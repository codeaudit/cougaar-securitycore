/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
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
 */


package org.cougaar.core.security.test.blackboard;


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OrgActivity;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;


/**
 * Malicious plugin that attempts to wrongfully delete org activity objects on
 * the blackboard. This plugin should have query privs. to the blackboard, but
 * not remove privs.
 *
 * @author ttschampel
 */
public class MaliciousBlackboardDeletePlugin extends AbstractBlackboardPlugin {

  /**
   * Load plugin
   */
  public void load() {
    super.load();
    this.setPluginName("MaliciousBlackboardDeletePlugin");
  }


  /**
   * try to delete a org activity
   */
  protected void queryBlackboard() {
    Collection collection = getBlackboardService().query(this.orgActivityPredicate);
    Iterator iterator = collection.iterator();
    if (iterator.hasNext()) {
      this.totalRuns++;
      OrgActivity orgActivity = (OrgActivity) iterator.next();
      try {
	getBlackboardService().publishRemove(orgActivity);
	if (logging.isWarnEnabled()) {
	  logging.warn("Could publishRemove OrgActivity - This plugin should NOT have the permission");
	}
        this.failures++;
      }
      catch (SecurityException e) {
	if (logging.isInfoEnabled()) {
	  logging.info("Unable to publishRemove OrgActivity - This is what we expected");
	}
	this.successes++;
      }
    }
  }
}
