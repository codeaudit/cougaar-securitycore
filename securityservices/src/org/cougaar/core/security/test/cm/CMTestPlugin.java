package org.cougaar.core.security.test.cm;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.cm.message.VerifyAgentAddRequest;
import org.cougaar.core.security.cm.message.VerifyResponse;
import org.cougaar.core.security.cm.relay.SharedDataRelay;
import org.cougaar.core.security.cm.service.CMService;
import org.cougaar.core.security.cm.service.CMServiceProvider;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;
/**
 *Plugin to test the CM. Will just request to add itself to the node passed in as the parameter
 * 
 * @author ttschampel
 *
 */
public class CMTestPlugin extends ComponentPlugin{
	
	private LoggingService logging;
	private String moveToNode = null;	
	private IncrementalSubscription subs=null;
	private CMService cmService = null;
	private UnaryPredicate predicate = new UnaryPredicate(){
		public boolean execute(Object o){
			
			if( o instanceof SharedDataRelay){
				SharedDataRelay sd = (SharedDataRelay)o;
				if(sd.getResponse()!=null
					&& sd.getResponse() instanceof VerifyResponse
					&& sd.getContent() instanceof VerifyAgentAddRequest
					&& ((VerifyAgentAddRequest)sd.getContent()).getAgent().equals(getAgentIdentifier().getAddress())){
						return true;
					}
			}
			
			return false;
		}
	};
	
	public void setLoggingService(LoggingService service){
		this.logging = service;
	}
	
	public void load(){
		super.load();
		Collection collection = this.getParameters();
		Iterator iterator = collection.iterator();
		if(iterator.hasNext()){
			moveToNode = (String)iterator.next();
		}else{
			if(logging.isErrorEnabled()){
				logging.error("CMTestPlugin has no test node parameter");
			}
		}
		cmService = (CMService)this.getServiceBroker().getService(this, CMService.class, null);
		if(cmService==null){
			this.getServiceBroker().addService(CMService.class, new CMServiceProvider(getServiceBroker()));
			cmService = (CMService)this.getServiceBroker().getService(this, CMService.class, null);
		
		}
		
	}
	
	public void setupSubscriptions(){
		this.subs = (IncrementalSubscription)this.getBlackboardService().subscribe(predicate);
		VerifyAgentAddRequest request = new VerifyAgentAddRequest(moveToNode, this.getAgentIdentifier().getAddress());
		cmService.sendMessage(request, getBlackboardService());
	}
	
	
	public void execute(){
		Enumeration enumeration = subs.getChangedList();
		while(enumeration.hasMoreElements()){
			SharedDataRelay  relay = (SharedDataRelay)enumeration.nextElement();
			VerifyResponse response = (VerifyResponse)relay.getResponse();
			if(logging.isInfoEnabled()){
				logging.info("CM Response:" + response.getValidRequest());
			}
		}
	}

}
