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
 * Tries to modify a org activity. Must have query permission for the org
 * activity and not have the modify permission
 *
 * @author ttschampel
 */
public class MaliciousBlackboardModifyPlugin extends AbstractBlackboardPlugin {
  private static final String ACTIVITY_NAME = "MaliciousBlackboardModifyPlugin";
  private IncrementalSubscription orgSubs = null;
  private UID modId = null;

  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    this.setPluginName("MaliciousBlackboardModifyPlugin");
  }


  /**
   * DOCUMENT ME!
   */
  public void setupSubscriptions() {
    super.setupSubscriptions();
    orgSubs = (IncrementalSubscription) getBlackboardService().subscribe(orgActivityPredicate);
  }


  /**
   * DOCUMENT ME!
   */
  public void execute() {
    super.execute();
    if (!this.wasAwakened()) {
      checkModified();
    }
  }


  private void checkModified() {
      this.totalRuns++;
      Enumeration enumeration = orgSubs.getChangedList();
      boolean found = false;
      while (enumeration.hasMoreElements()) {
        OrgActivity orgActivity = (OrgActivity) enumeration.nextElement();
        if (orgActivity.getUID().equals(modId)) {
          found = true;
          break;
        }
      }
      if (found) {
        this.failures++;
        if (logging.isWarnEnabled()) {
          logging.warn("Was able to modify OrgActivity Object!");
        }

        this.createIDMEFEvent(pluginName, "Able to modify OrgActivity on the Blackboard!");
      } else {
        this.successes++;
      }
  }


  /**
   * Try to modify a org activity
   */
  protected void queryBlackboard() {
    Collection collection = this.getBlackboardService().query(this.orgActivityPredicate);
    Iterator iterator = collection.iterator();
    if (iterator.hasNext()) {
      OrgActivity orgActivity = (OrgActivity) iterator.next();
      try {
        orgActivity.setActivityName(ACTIVITY_NAME);
      }
      catch (SecurityException e) {
        if (logging.isInfoEnabled()) {
          logging.info("Unable to setActivityName");
        }
      }
      this.modId = orgActivity.getUID();
      this.totalRuns++;
      try {
	getBlackboardService().publishChange(orgActivity);
        this.failures++;
        this.createIDMEFEvent(pluginName, "Able to publishChange OrgActivity");
      }
      catch (SecurityException e) {
        this.successes++;
      }
    } else {
      this.modId = null;

    }
  }
}
