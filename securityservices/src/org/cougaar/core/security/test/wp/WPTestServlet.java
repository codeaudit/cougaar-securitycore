package org.cougaar.core.security.test.wp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.security.test.AbstractServletComponent;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;

public class WPTestServlet extends AbstractServletComponent{

	
	protected String getPath() {
		return "/wptest";
	}

	/* (non-Javadoc)
	 * @see org.cougaar.core.security.test.AbstractServletComponent#execute(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	protected void execute(HttpServletRequest request, HttpServletResponse response) {
		this.blackboardService.openTransaction();
		PlanningFactory pf = (PlanningFactory)domainService.getFactory("planning");
		NewTask task = pf.newTask();
		task.setVerb(Verb.getVerb("WPTEST"));
		this.blackboardService.closeTransactionDontReset();
		
	}

}
