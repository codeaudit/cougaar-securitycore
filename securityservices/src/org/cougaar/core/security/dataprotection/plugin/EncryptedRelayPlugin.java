package org.cougaar.core.security.dataprotection.plugin;

import java.util.Enumeration;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.DataProtectionKey;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.util.UnaryPredicate;

/**
 * Receives Encrypted keys through relay
 * @author ttschampel
 *
 */
public class EncryptedRelayPlugin extends ComponentPlugin {
  /**Plugin name*/
  private static final String pluginName="EncryptedRelayPlugin";
  
  /**Logging Service*/
  private LoggingService logging = null;
  public void setLoggingService(LoggingService s){
  	logging =s;
  }
  /**Subscription to Relay*/
  private IncrementalSubscription subs = null;
  /**Predicate for relay*/
  private UnaryPredicate predicate = new UnaryPredicate(){
  	public boolean execute(Object o){
  		if(o instanceof SharedDataRelay){
  			SharedDataRelay sdr = (SharedDataRelay)o;
  			return sdr.getContent()!=null && sdr.getContent() instanceof DataProtectionKey;
  		}
  		return false;
  	}
  };
  /**UIDService*/
  UIDService uidService = null;
  
  public void load(){
  	super.load();
  	uidService = (UIDService)this.getServiceBroker().getService(this, UIDService.class, null);
  }
	/**
	 * Setup subscriptions
	 */
	protected void setupSubscriptions() {
		subs = (IncrementalSubscription)getBlackboardService().subscribe(predicate);
		
	}

	/**
	 * Process subscription
	 */
	protected void execute() {
		if(logging.isDebugEnabled()){
			logging.debug(pluginName + " executing");
		}
		Enumeration enumeration = subs.getAddedList();
		while(enumeration.hasMoreElements()){
			SharedDataRelay sdr = (SharedDataRelay)enumeration.nextElement();
			DataProtectionKey key = (DataProtectionKey)sdr.getContent();
			String agent = sdr.getSource().getAddress();
			long timestamp = System.currentTimeMillis();
			if(logging.isDebugEnabled()){
				logging.debug("Got data protection key from " + agent);
			}
			DataProtectionKeyContainer container = new DataProtectionKeyContainer();
			container.setAgentName(agent);
			container.setTimestamp(timestamp);
			container.setKey(key);
			container.setUID(uidService.nextUID());
			getBlackboardService().publishAdd(container);
			getBlackboardService().publishRemove(sdr);
		}
	}

}
