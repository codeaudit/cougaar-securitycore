package org.cougaar.core.security.monitoring.blackboard;

import java.util.*;

import org.cougaar.core.domain.Domain;
import org.cougaar.core.domain.Factory;
import org.cougaar.core.domain.LDMServesPlugin;
import org.cougaar.core.blackboard.LogPlan;
import org.cougaar.core.blackboard.BlackboardServesLogicProvider;
import org.cougaar.core.blackboard.LogPlanServesLogicProvider;
import org.cougaar.core.agent.ClusterServesLogicProvider;
import org.cougaar.core.blackboard.XPlanServesBlackboard;
import org.cougaar.core.agent.LogicProvider;

/**
 * Create a barebones CmrDomain.  We have our own Factory, and
 * will have at least one logic provider.
 * The property to load this Domain is:<pre>
 *         -Dorg.cougaar.domain.cmr=org.cougaar.core.security.monitoring.blackboard.CmrDomain
 * </pre>
 **/
public class CmrDomain implements Domain {
  public CmrDomain() { }

  public Factory getFactory(LDMServesPlugin ldm) {
    return new CmrFactory(ldm);
  }

  // Could initialize constants used in the domain here, for example
  public void initialize() { }

  // Here we say that we're just going to use the same basic
  // blackboard as everyone else.
  // You could create your own blackboard, but I'm honestly not
  // sure what's entailed with that, or what it buys you
  public XPlanServesBlackboard createXPlan(Collection existingXPlans) {

    for (Iterator plans = existingXPlans.iterator(); plans.hasNext(); ) {
      XPlanServesBlackboard xPlan = (XPlanServesBlackboard) plans.next();
      if (xPlan != null) return xPlan;
    }
    
    return new LogPlan();
  }  

  public Collection createLogicProviders(BlackboardServesLogicProvider logplan,
					 ClusterServesLogicProvider cluster) {

      ArrayList l = new ArrayList(1);
      // Add your LPs to the blackboard. You add LPs to the blackboard
      // so they can watch things that get published.
      // You must give them a reference to the Agent so they can send
      // messages
      //l.add(new ImpactsLP((LogPlanServesLogicProvider)logplan, cluster));
      return l;
  }
}
