package org.cougaar.core.security.test.blackboard;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OrgActivity;

/**
 * Malicious plugin that attempts to wrongfully delete
 * 	org activity objects on the blackboard. This plugin
 *  should have query privs. to the blackboard, but not
 *  remove privs.
 * 
 * @author ttschampel
 *
 */
public class MaliciousBlackboardDeletePlugin extends AbstractBlackboardPlugin{
	private UID deleteUID=null;
	private IncrementalSubscription orgSubs;
	
	/**
	 * Execute
	 */
	public void execute(){
		super.execute();
		checkDeletedActivies();
	}
	
	public void setupSubscriptions(){
		super.setupSubscriptions();
		orgSubs = (IncrementalSubscription)getBlackboardService().subscribe(this.orgActivityPredicate);
	}
	
	private void checkDeletedActivies(){
		if(deleteUID!=null){
			Enumeration enum = orgSubs.getRemovedList();
			while(enum.hasMoreElements()){
				OrgActivity orgAct = (OrgActivity)enum.nextElement();
				if(orgAct.getUID().equals(deleteUID)){
					if(logging.isDebugEnabled()){
						logging.debug("Was Able to delete an OrgActivity!");
					}
					this.successes--;
					this.failures++;
					this.createIDMEFEvent(pluginName,"Was able to delete a OrgActivity from the Blackboard");
				}
			}	
		}
	}
	
	/**
	 * Load plugin
	 */
	public void load(){
		super.load();
		this.setPluginName("MaliciousBlackboardDeletePlugin");
	}
	
	/**
	 * try to delete a org activity
	 */
	protected void queryBlackboard() {
		Collection collection = getBlackboardService().query(this.orgActivityPredicate);
		Iterator iterator = collection.iterator();
		if(iterator.hasNext()){
			OrgActivity orgActivity = (OrgActivity)iterator.next();
			this.deleteUID = orgActivity.getUID();
			getBlackboardService().publishRemove(orgActivity);
			this.totalRuns++;
			this.successes++;
		}else{
			this.deleteUID = null;
		}
		
	}

}
