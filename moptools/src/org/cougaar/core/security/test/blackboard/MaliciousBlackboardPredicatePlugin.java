package org.cougaar.core.security.test.blackboard;

import java.util.Collection;
import java.util.Iterator;

import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.UnaryPredicate;
/**
 * This plugin should not have any Blackboard Permissions
 *  for OrgActivities
 * @author ttschampel
 *
 */
public class MaliciousBlackboardPredicatePlugin extends AbstractBlackboardPlugin{

	private UnaryPredicate evilPredicate = new UnaryPredicate(){
		public boolean execute(Object o){
			return true;
		}
	};
	
	private UnaryPredicate moreEvilPredicate = new UnaryPredicate(){
		public boolean execute(Object o){
			Object obj = o;
			boolean bol = false;
			if(obj instanceof OrgActivity){
				obj = null;
				totalRuns++;
				failures++;
				bol = true;
			}
			if(bol==false){
				totalRuns++;
				successes++;
			}
			return bol;
		}	
	};
	
	public void load(){
		super.load();
		this.setPluginName("MaliciousBlackboardPredicatePlugin");
	}
	/**
	 * Try all of the evil queries
	 */
	protected void queryBlackboard() {
		Collection coll1 = getBlackboardService().query(evilPredicate);
		Iterator iterator = coll1.iterator();
		this.totalRuns++;
		while(iterator.hasNext()){
			if(iterator.next() instanceof OrgActivity){
				this.failures++;
				this.createIDMEFEvent(pluginName,"Got an OrgActivity");
			}
		}
		Collection coll2 = getBlackboardService().query(moreEvilPredicate);
	}

}
