package org.cougaar.core.security.test.blackboard;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.util.UnaryPredicate;

/**
 *Tries to modify a org activity. Must have query permission
 *  for the org activity and not have the modify permission
 *  
 * @author ttschampel
 *
 */
public class MaliciousBlackboardModifyPlugin extends AbstractBlackboardPlugin{

	private static final String ACTIVITY_NAME="MaliciousBlackboardModifyPlugin";
	private IncrementalSubscription orgSubs = null;
	private UnaryPredicate changedPredicate = new UnaryPredicate(){
		public boolean execute(Object o){
			if(o instanceof OrgActivity){
				OrgActivity orgA = (OrgActivity)o;
				return orgA.getActivityName().equals(ACTIVITY_NAME);
			}	
			return false;	
		}
	};
	
	public void load(){
		super.load();
		this.setPluginName("MaliciousBlackboardModifyPlugin");
	}

	
	public void setupSubscriptions(){
		super.setupSubscriptions();
		orgSubs = (IncrementalSubscription)getBlackboardService().subscribe(changedPredicate);
	}
	
	public void execute(){
		super.execute();
		checkModified();
	}
	
	
	private void checkModified(){
			Enumeration enumeration = orgSubs.getChangedList();
			while(enumeration.hasMoreElements()){
				this.successes--;
				this.failures++;
				this.createIDMEFEvent(pluginName,"Able to modify OrgActivity on the Blackboard!");
			}
	}
	
	
	/**
	 * Try to modify a org activity
	 *
	 */
	protected void queryBlackboard() {
		Collection collection = this.getBlackboardService().query(this.orgActivityPredicate);
		Iterator iterator = collection.iterator();
		if(iterator.hasNext()){
			OrgActivity orgActivity = (OrgActivity)iterator.next();
			orgActivity.setActivityName(ACTIVITY_NAME);
			getBlackboardService().publishChange(orgActivity);
			this.totalRuns++;
			this.successes++;
		}
		
	}
}
