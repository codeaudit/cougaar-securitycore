package org.cougaar.core.security.test.blackboard;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.util.UID;
import org.cougaar.glm.ldm.oplan.OrgActivity;

/**
 * Subscribes to changes in OrgActivities (Changes are published by itself).
 * This plugin should have Query access and modify access to the OrgActivity
 * Objects on the Blackboard. 
 * @author ttschampel
 *
 */
public class LegitimateBlackboardSubcribePlugin extends AbstractBlackboardPlugin{
	/**The Modified OrgActivity UID */
	private UID modUID = null;
	
	private IncrementalSubscription orgSubs = null;
	
	/**
	 * Setup subscription to changed org activities
	 */
	public void setupSubscriptions(){
		super.setupSubscriptions();
		this.orgSubs = (IncrementalSubscription)getBlackboardService().subscribe(this.orgActivityPredicate);
	}
	/**
	 * Process subscriptions
	 */
	public void execute(){
		super.execute();
		checkForChangedActivities();
	}
	/**
	 * Load plugin
	 */
	public void load(){
		super.load();
		this.setPluginName("LegitimateBlackboardSubcribePlugin");
	}
	/**
	 * Query Blackboard for a OrgActivity and change the first one
	 */
	protected void queryBlackboard() {
		Collection collection = getBlackboardService().query(this.orgActivityPredicate);
		Iterator iterator = collection.iterator();
		if(iterator.hasNext()){
			OrgActivity orgActivity = (OrgActivity)iterator.next();
			this.modUID = orgActivity.getUID();
			getBlackboardService().publishChange(orgActivity);
		}else{
			this.modUID = null;
		}	
		
	}
	
	/**
	 * Check subscription for the changed org activity
	 *
	 */
	private void checkForChangedActivities(){
		if(modUID!=null){
			this.totalRuns++;
			Enumeration enumeration = orgSubs.getChangedList();
			boolean foundIt = false;
			
			while(enumeration.hasMoreElements()){
				OrgActivity orgActivity = (OrgActivity)enumeration.nextElement();
				if(orgActivity.getUID().equals(modUID)){
					foundIt = true;
					break;
				}
			}
			if(foundIt){
				this.successes++;
			}else{
				this.failures++;
				this.createIDMEFEvent(pluginName, "Could not get publishChange notification for orgActivity:" + this.modUID);
			}
			this.modUID = null;
		}
	}
}
