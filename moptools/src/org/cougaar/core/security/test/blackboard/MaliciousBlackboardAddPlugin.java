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
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.UnaryPredicate;

import java.util.Enumeration;


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
  private UID addUID = null;

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
    orgActivitySubs = (IncrementalSubscription) getBlackboardService().subscribe(this.orgActivityPredicate);

  }


  /**
   * checks for newly added org activities using the
   * checkForAddedOrgActivitySubs()
   */
  public void execute() {
    super.execute();
    if(!this.wasAwakened()){
    	checkForAddedOrgActivitySubs();
    }
  }


  private void checkForAddedOrgActivitySubs() {
    if (addUID != null) {
      Enumeration enumeration = this.orgActivitySubs.getAddedList();
      if (logging.isDebugEnabled()) {
        logging.debug("Check for Added Org Activity....");
      }

      boolean found = false;
      while (enumeration.hasMoreElements()) {
        OrgActivity orgActivity = (OrgActivity) enumeration.nextElement();
        if (orgActivity.getUID().equals(addUID)) {
          found = true;
          break;
        }
      }

       if (found) {
         if (logging.isDebugEnabled()) {
           logging.debug("Found added org activity");
         }
         //failure
         this.failures++;
         //create IDMEF Event
         this.createIDMEFEvent(pluginName, "Was able to add OrgActivity object");
         } else {
         	if(logging.isDebugEnabled()){
         		logging.debug("did not find it");
         	}
           this.successes++;
         }
      
    }
  }


  /**
   * Try to add a OrgActivity Object to the blackboard
   */
  protected void queryBlackboard() {
    //automatically increment success
    OrgActivity orgActivity = OplanFactory.newOrgActivity(pluginName, uidService.nextUID());
    orgActivity.setActivityName(MALCICOUS_ADD_ACTIVITY_NAME);
    orgActivity.setUID(uidService.nextUID());
    getBlackboardService().publishAdd(orgActivity);
    this.addUID = orgActivity.getUID();
    this.totalRuns++;
  }
}
