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
 * Created on Jun 4, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import java.util.Collection;
import java.util.Iterator;

import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.glm.ldm.oplan.OrgActivityImpl;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.mts.MessageAddress;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class LegitimateBlackboardPlugin extends AbstractBlackboardPlugin {
  private UID addUID = null;

  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    setPluginName("LegitimateBlackboardPlugin");
  }

  /**
   * Query for org activities and produce idmef event when  org activities
   * should be present, but can't get any through querying the blacboard
   */
  protected void queryBlackboard() {
    Collection orgActivities = getBlackboardService().query(this.orgActivityPredicate);
    Iterator iter = orgActivities.iterator();
    this.totalRuns++;
    if (iter.hasNext()) {
      //success	
      this.successes++;
    } else {
      // Try to add OrgActivity objects to the blackboard with a fake OrgActivity
      publishAddOrgActivity();
    }
  }

  private void publishAddOrgActivity() {
    OrgActivity oa = OplanFactory.newOrgActivity(pluginName, uidService.nextUID());
    oa.setActivityName("LegitimatePlugingActivityName");
    oa.setUID(uidService.nextUID());
    MessageAddress ma = null;
    AgentIdentificationService ais = (AgentIdentificationService)
      getServiceBroker().getService(this, AgentIdentificationService.class, null);
    if(ais != null) {
      ma = ais.getMessageAddress(); 
      getServiceBroker().releaseService(this, AgentIdentificationService.class, ais);
    }
    else {
      if (logging.isWarnEnabled()) {
	logging.warn("Unable to get AgentIdentificationService");
      }
    }
    ((OrgActivityImpl)oa).setOwner(ma);
    this.addUID = oa.getUID();

    try {
      this.totalRuns++;
      getBlackboardService().publishAdd(oa);
      this.successes++;
    }
    catch (Exception e) {
      if (logging.isWarnEnabled()) {
	logging.warn("Unable to publishAdd OrgActivity!", e);
      }
      this.failures++;
      this.createIDMEFEvent(pluginName, "Can't access OrgActivity object: " + e);
    }

    // Try to query again
    Collection orgActivities = getBlackboardService().query(this.orgActivityPredicate);
    Iterator iter = orgActivities.iterator();
    if (!iter.hasNext()) {
      //failure
      this.failures++;
      this.createIDMEFEvent(pluginName, "Can't access OrgActivity object");
    }
    try {
      this.totalRuns++;
      getBlackboardService().publishRemove(oa);
      this.successes++;
    }
    catch (Exception e) {
      if (logging.isWarnEnabled()) {
	logging.warn("Unable to publishRemove OrgActivity!", e);
      }
      this.failures++;
      this.createIDMEFEvent(pluginName, "Can't access OrgActivity object: " + e);
    }
  }
}
