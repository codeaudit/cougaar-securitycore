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
 * Should have access to delete and to query OrgActivity objects on the
 * Blackboard.
 *
 * @author ttschampel
 */
public class LegitimateBlackboardDeletePlugin extends AbstractBlackboardPlugin {
  /** Subscription to OrgActivity */
  private IncrementalSubscription orgSubs = null;
  /** UID of last deleted Org Activity */
  private UID deleteUID = null;

  /**
   * Load component and plugin name
   */
  public void load() {
    super.load();
    this.setPluginName("LegitimateBlackboardDeletePlugin");
  }


  /**
   * Setup subscription to org activity
   */
  public void setupSubscriptions() {
    super.setupSubscriptions();
    orgSubs = (IncrementalSubscription) getBlackboardService().subscribe(this.orgActivityPredicate);
  }


  /**
   * Process Subscriptions
   */
  public void execute() {
    super.execute();
    checkDeletedActivities();
  }


  /**
   * Check to confirm we get the deleted notification
   */
  private void checkDeletedActivities() {
    if (deleteUID != null) {
      boolean foundIt = false;
      Enumeration enumeration = orgSubs.getRemovedList();
      while (enumeration.hasMoreElements()) {
        OrgActivity orgActivity = (OrgActivity) enumeration.nextElement();
        if (orgActivity.getUID().equals(deleteUID)) {
          foundIt = true;
        }
      }

      if (foundIt == false) {
        this.failures++;
        this.successes--;
        this.createIDMEFEvent(pluginName, "Did not delete org activity");
      }
    }
  }


  /**
   * Remove org activity
   */
  protected void queryBlackboard() {
    Collection collection = getBlackboardService().query(this.orgActivityPredicate);
    Iterator iterator = collection.iterator();
    if (iterator.hasNext()) {
      OrgActivity act = (OrgActivity) iterator.next();
      this.deleteUID = act.getUID();
      this.totalRuns++;
      this.successes++;
    } else {
      this.deleteUID = null;
    }
  }
}
