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
import org.cougaar.util.UnaryPredicate;


/**
 * Plugin that Maliciously tries to add Org Activity Objects to the blackboard.
 * This plugin should have Query permission for Org Activities on the
 * blackboard, so it can check for the newly added OrgActivities on the
 * blackboard
 */
public class MaliciousBlackboardAddPlugin extends AbstractBlackboardPlugin {
  private static final String MALCICOUS_ADD_ACTIVITY_NAME = "ADDED BY MALICIOUS BLACKBOARD ADD PLUGIN";

  //subscription to org activitys
  private IncrementalSubscription orgActivitySubs = null;
  private UnaryPredicate myorgActivityPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OrgActivity) {
          OrgActivity orgA = (OrgActivity) o;
          return (orgA.getActivityName() != null)
          && orgA.getActivityName().equals(MALCICOUS_ADD_ACTIVITY_NAME);
        }

        return false;
      }
    };

  /**
   *
   */
  public void load() {
    super.load();
    setPluginName("MaliciousBlackboardAddPlugin");
  }


  /**
   * set up subscription to the org activities
   */
  public void setupSubscriptions() {
    super.setupSubscriptions();
    //add subscription to org activities
    orgActivitySubs = (IncrementalSubscription) getBlackboardService()
                                                  .subscribe(this.myorgActivityPredicate);

  }


  /**
   * checks for newly added org activities using the
   * checkForAddedOrgActivitySubs()
   */
  public void execute() {
    super.execute();
    checkForAddedOrgActivitySubs();
  }


  private void checkForAddedOrgActivitySubs() {
    Enumeration enumeration = this.orgActivitySubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      //failure
      this.failures++;
      this.successes--;
      //create IDMEF Event
      this.createIDMEFEvent(pluginName, "Was able to add OrgActivity object");
    }
  }


  /**
   * Try to add a OrgActivity Object to the blackboard
   */
  protected void queryBlackboard() {
    //automatically increment success
    OrgActivity orgActivity = OplanFactory.newOrgActivity(pluginName,new UID(pluginName,3434343));
    orgActivity.setActivityName(MALCICOUS_ADD_ACTIVITY_NAME);
    getBlackboardService().publishAdd(orgActivity);
    this.successes++;
    this.totalRuns++;
  }
}
