package org.cougaar.core.security.test.cm;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.test.AbstractServletComponent;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;
/**
 *Servlet to test the Configuration Manager. When invoked, it will publish a Task to the 
 *Blackboard which is subscribed to by the CMTestPlugin.  The URL Param <i>node</i> will
 *be passed to the plugin as the node name to try to move this agent to.  An Example test would 
 *be to pass the name of a Management node to this servlet while this agent is not on a management 
 *node. and vice versa. 
 * @author ttschampel
 *
 */
public class CMTestServlet extends AbstractServletComponent{

	public static final String CM_TEST_VERB="CMTESTVERB";
	public static final String DEST_NODE_PREP="DESTNODEPREP";
	public static final String NODE_URL_PARAM="node";
	
	/**
	 * Get Path to the Servlet
	 */
	protected String getPath() {
		return "/testCMServlet";
	}

/**
 * process requeest
 */
	protected void execute(HttpServletRequest request, HttpServletResponse response) {
		String node = request.getParameter(NODE_URL_PARAM);
		if(node==null || node.trim().length()==0){
			if(logging.isErrorEnabled()){
				logging.error("Must pass node name as using node url parameter");
			}
		}else{
			PlanningFactory ldm = (PlanningFactory)domainService.getFactory("planning");
			NewTask task = ldm.newTask();
			task.setVerb(Verb.getVerb(CM_TEST_VERB));
			NewPrepositionalPhrase nodePrep = ldm.newPrepositionalPhrase();
			nodePrep.setPreposition(DEST_NODE_PREP);
			nodePrep.setIndirectObject(node);
			task.addPrepositionalPhrase(nodePrep);
			this.blackboardService.openTransaction();
			this.blackboardService.publishAdd(task);
			this.blackboardService.closeTransactionDontReset();
		}
		
	}

}
