/* 
 * <copyright>
 * Copyright 2002 BBNT Solutions, LLC
 * under sponsorship of the Defense Advanced Research Projects Agency (DARPA).

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Cougaar Open Source License as published by
 * DARPA on the Cougaar Open Source Website (www.cougaar.org).

 * THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 * PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 * IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 * ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 * HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 * TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */
package org.cougaar.core.security.monitoring.blackboard;

import java.util.Collection;
import java.util.Iterator;

import org.cougaar.core.agent.ClusterServesLogicProvider;
import org.cougaar.core.blackboard.LogPlan;
import org.cougaar.core.blackboard.XPlanServesBlackboard;
import org.cougaar.core.domain.Domain;
import org.cougaar.core.domain.DomainAdapter;
import org.cougaar.core.domain.DomainBindingSite;


/**
 * Create a barebones CmrDomain.  We have our own Factory
 * The property to load this Domain is:<pre>
 *         -Dorg.cougaar.domain.cmr=org.cougaar.core.security.monitoring.blackboard.CmrDomain
 * </pre>
 **/
public class CmrDomain extends DomainAdapter {
  private static final String CMR_NAME = "cmr".intern();

  public String getDomainName() {
    return CMR_NAME;
  }

  public CmrDomain() { }

  // Could initialize constants used in the domain here, for example
  public void initialize() {
    super.initialize();
    System.out.println("Just to check whether initialize of cmr domain is called: ****************"); 
  }

  protected void loadFactory() {
    DomainBindingSite bindingSite = (DomainBindingSite) getBindingSite();

    if (bindingSite == null) {
      throw new RuntimeException("Binding site for the Cmr domain has not be set.\n" +
                             "Unable to initialize Cmr domain Factory without a binding site.");
    } 

    setFactory(new CmrFactory(bindingSite.getClusterServesLogicProvider().getLDM()));
  }
    
  // Here we say that we're just going to use the same basic
  // blackboard as everyone else.
  // You could create your own blackboard, but I'm honestly not
  // sure what's entailed with that, or what it buys you
  protected void loadXPlan() {
    DomainBindingSite bindingSite = (DomainBindingSite) getBindingSite();

    if (bindingSite == null) {
      throw new RuntimeException("Binding site for the Cmr domain has not be set.\n" +
                             "Unable to initialize Cmr domain XPlan without a binding site.");
    } 

    Collection xPlans = bindingSite.getXPlans();
    XPlanServesBlackboard logPlan = null;
    
    for (Iterator iterator = xPlans.iterator(); iterator.hasNext();) {
      XPlanServesBlackboard  xPlan = (XPlanServesBlackboard) iterator.next();
      if (xPlan instanceof LogPlan) {
        // Note that this means there are 2 paths to the plan.
        // Is this okay?
        logPlan = xPlan;
        break;
      }
    }
    
    if (logPlan == null) {
      logPlan = new LogPlan();
    }
    
    setXPlan(logPlan);
  }

  protected void loadLPs() {
    DomainBindingSite bindingSite = (DomainBindingSite) getBindingSite();

    if (bindingSite == null) {
      throw new RuntimeException("Binding site for the Cmr domain has not be set.\n" +
                             "Unable to initialize Cmr domain LPs without a binding site.");
    } 

    ClusterServesLogicProvider cluster =
      bindingSite.getClusterServesLogicProvider();

    // Most LPs actually need a LogPlanServesLogicProvider. The only XPlan that implements
    // that (actually, the only one anywhere), is the LogPlan. So cast it.
    LogPlan logPlan = (LogPlan) getXPlan();

    //addLogicProvider(new ImpactsLP(logPlan, cluster));;
  }

}
