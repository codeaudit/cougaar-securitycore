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
import java.io.Serializable;
import java.util.Enumeration;

import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OplanFactory;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.glm.ldm.oplan.OrgActivityImpl;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.blackboard.IncrementalSubscription;

/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public class LegitimateBlackboardPlugin extends AbstractBlackboardPlugin {
  private UID addUID = null;
  /** Subscription to OrgActivityStatus objects */
  private IncrementalSubscription orgStatusSubscription;

  protected UnaryPredicate orgActivityStatusPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return (o instanceof OrgActivityStatus);
    }
  };

  /**
   * DOCUMENT ME!
   */
  public void load() {
    super.load();
    setPluginName("LegitimateBlackboardPlugin");
  }

  public void setupSubscriptions() {
    super.setupSubscriptions();
    orgStatusSubscription = (IncrementalSubscription)
      getBlackboardService().subscribe(orgActivityStatusPredicate);
  }

  /**
   * Process subscriptions
   */
  public void execute() {
    Enumeration enum = orgStatusSubscription.getAddedList();
    if (enum.hasMoreElements()) {
      if (logging.isDebugEnabled()) {
	logging.debug("New element in orgStatusSubscription.getAddedList");
      }
      // We previously added a fake OrgActivity object on the blackboard.
      queryOrgActivity(true);
      OrgActivityStatus oas = (OrgActivityStatus) enum.nextElement();
      // Now that we tested, remove the OrgActivity.
      publishRemoveOrgActivity(oas);
    }

    super.execute();
  }

  /**
   * Query for org activities and produce idmef event when  org activities
   * should be present, but can't get any through querying the blacboard
   */
  protected void queryBlackboard() {
    Enumeration enum = orgStatusSubscription.getAddedList();
    if (!enum.hasMoreElements()) {
      // We did not add a fake orgactivity object on the blackboard.
      // That does not mean there is necessarily one already.
      // We might have to add one.
      if (logging.isDebugEnabled()) {
	logging.debug("No new element in orgStatusSubscription.getAddedList");
      }
      queryOrgActivity(false);
    }
  }

  private void publishAddOrgActivity() {
    if (logging.isDebugEnabled()) {
      logging.debug("publishAddOrgActivity");
    }
    OrgActivity oa = OplanFactory.newOrgActivity(pluginName, uidService.nextUID());
    oa.setActivityName("LegitimatePlugingActivityName");
    oa.setActivityType("LegitimatePlugingActivityType");
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

      // Create and publishAdd an orgActivityStatus object,
      // so next time we will check the object and remove it from the
      // blackboard.
      if (logging.isDebugEnabled()) {
	logging.debug("Publish OrgActivityStatus");
      }
      OrgActivityStatus oas = new OrgActivityStatus(oa);
      getBlackboardService().publishAdd(oas);
    }
    catch (Exception e) {
      if (logging.isWarnEnabled()) {
	logging.warn("Unable to publishAdd OrgActivity!", e);
      }
      this.failures++;
      this.createIDMEFEvent(pluginName, "Can't publishAdd OrgActivity object: " + e);
    }
  }

  private void queryOrgActivity(boolean expectOrgActivity) {
    if (logging.isDebugEnabled()) {
      logging.debug("queryOrgActivity: " + expectOrgActivity);
    }
    Collection orgActivities =
      getBlackboardService().query(this.orgActivityPredicate);
    Iterator iter = orgActivities.iterator();
    if (expectOrgActivity) {
      // failure - There should have been an OrgActivity object.
      this.totalRuns++;
      if (!iter.hasNext()) {
	this.failures++;
	this.createIDMEFEvent(pluginName, "Can't access OrgActivity object");
      }
      else {
	this.successes++;
      }
    } else {
      // Maybe there was really no OrgActivity object on the blackboard.
      // Create a fake orgActivity object and publish it.
      // See if we can query it, and remove the object after we
      // read it.
      publishAddOrgActivity();
    }
  }

  private void publishRemoveOrgActivity(OrgActivityStatus oas) {
    if (logging.isDebugEnabled()) {
      logging.debug("publishRemoveOrgActivity");
    }
    OrgActivity oa = oas.getOrgActivity();
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

  private static class OrgActivityStatus implements Serializable {
    private OrgActivity theOrgActivity;
    public OrgActivityStatus(OrgActivity oa) {
      theOrgActivity = oa;
    }
    public OrgActivity getOrgActivity() {
      return theOrgActivity;
    }
  }

}
