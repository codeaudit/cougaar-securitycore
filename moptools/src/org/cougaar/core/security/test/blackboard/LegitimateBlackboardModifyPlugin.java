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
 * Should have query and modify permission for  OrgActivity blackboard objects.
 * Just modifies Org Activity Objects and checks to see if they  have been
 * changed.
 *
 * @author ttschampel
 */
public class LegitimateBlackboardModifyPlugin extends AbstractBlackboardPlugin {
  /** Subscription to orgActivity */
  private IncrementalSubscription orgSubs = null;
  /** Modified org activity uid */
  private UID modUID = null;

  /**
   * Load component
   */
  public void load() {
    super.load();
    this.setPluginName("LegitimateBlackboardModifyPlugin");
  }


  /**
   * Process Subscriptions
   */
  public void execute() {
    super.execute();
    checkModOrgActivities();
  }


  /**
   * Setup subscriptions
   */
  public void setupSubscriptions() {
    super.setupSubscriptions();
    orgSubs = (IncrementalSubscription) getBlackboardService().subscribe(orgActivityPredicate);
  }


  /**
   * Modify org activity
   */
  protected void queryBlackboard() {
    Collection collection = getBlackboardService().query(orgActivityPredicate);
    Iterator iterator = collection.iterator();
    if (iterator.hasNext()) {
      OrgActivity orgAct = (OrgActivity) iterator.next();
      this.modUID = orgAct.getUID();
      this.totalRuns++;
      this.successes++;
    } else {
      this.modUID = null;
    }
  }


  /**
   * Check to see if we receive the changed org activity
   */
  private void checkModOrgActivities() {
    if (modUID != null) {
      Enumeration enumeration = orgSubs.getChangedList();
      boolean changed = false;
      while (enumeration.hasMoreElements()) {
        OrgActivity org = (OrgActivity) enumeration.nextElement();
        if (org.getUID().equals(modUID)) {
          changed = true;
        }
      }

      if (changed == false) {
        this.createIDMEFEvent(pluginName,
          "Could not change OrgActivity on blackboard");
        this.successes--;
        this.failures++;
      }
    }
  }
}
