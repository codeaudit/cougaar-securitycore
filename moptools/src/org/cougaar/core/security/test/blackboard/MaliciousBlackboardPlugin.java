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


/*
 * Created on May 30, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import java.util.Collection;


/**
 * Queries the blackboard for OrgActivity objects every X seconds.  The time
 * interval is changed according to the OperatingMode by detecting changes in
 * the operating mode through a subscription.   If plugin gets any OrgActivity
 * objects from a blackboard query an IDMEF Alert is created and published to
 * the Blackboard.
 *
 * @author ttschampel
 */
public class MaliciousBlackboardPlugin extends AbstractBlackboardPlugin {
  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    setPluginName("MaliciousBlackboardPlugin");
  }


  /**
   * Query for org activities and create new IDMEF Event during failure
   */
  protected void queryBlackboard() {
    Collection orgActivities = getBlackboardService().query(this.orgActivityPredicate);
    this.totalRuns++;
    if (orgActivities.size() > 0) {
      if (logging.isInfoEnabled()) {
        logging.info("******************************************Found :"
          + orgActivities.size() + " org activities");
      }

      this.createIDMEFEvent(pluginName, "Was able to access OrgActivity object");
      this.failures++;
    } else {
      this.successes++;
    }
  }
}
