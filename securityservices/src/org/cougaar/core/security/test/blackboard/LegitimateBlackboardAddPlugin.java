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


import java.util.Enumeration;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.glm.ldm.oplan.OrgActivity;


/**
 * Needs to have Query and Add permission for Org     Activities on the
 * blackboard
 *
 * @author ttschampel
 */
public class LegitimateBlackboardAddPlugin extends AbstractBlackboardPlugin {
  /** Activity UID for tracking purposes */
  private UID actUID = null;
  /** Subscription to org activities */
  private IncrementalSubscription orgSubs = null;

  /**
   * Load component
   */
  public void load() {
    super.load();
    this.setPluginName("LegitimateBlackboardAddPlugin");
  }


  /**
   * Setup subscription
   */
  public void setupSubscriptions() {
    super.setupSubscriptions();
    orgSubs = (IncrementalSubscription) getBlackboardService().subscribe(orgActivityPredicate);
  }


  /**
   * Process subscriptions
   */
  public void execute() {
    super.execute();
    checkAddedActivity();

  }


  /**
   * Check that org activity was added
   */
  private void checkAddedActivity() {
    Enumeration enumeration = orgSubs.getAddedList();
    if (actUID != null) {
      boolean added = false;

      while (enumeration.hasMoreElements()) {
        OrgActivity orgAct = (OrgActivity) enumeration.nextElement();
        if (orgAct.equals(actUID)) {
          added = true;
        }
      }

      if (added == false) {
      	this.failures++;
      	this.successes--;
      	this.createIDMEFEvent(pluginName,"Could not add OrgActivity to blackboard");
      }
    }
  }


  /**
   * Add Org Activity
   */
  protected void queryBlackboard() {
	OrgActivity orgActivity = OplanFactory.newOrgActivity(pluginName,new UID(pluginName,3434343));
    this.actUID = orgActivity.getUID();
    getBlackboardService().publishAdd(orgActivity);
    this.successes++;
    this.totalRuns++;

  }
}
