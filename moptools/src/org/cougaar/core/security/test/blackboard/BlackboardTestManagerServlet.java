/*
 * Created on Jun 5, 2003
 *
 * 
 */
package org.cougaar.core.security.test.blackboard;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.Verb;

import com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent;
/**
 * @author ttschampel
 *
 */
public class BlackboardTestManagerServlet extends AdvancedSimpleServletComponent{
  public static final String DO_PARAM="do";
  public static final String EXP_PARAM="exp";
  public static final String START_TESTING="start";
  public static final String END_TESTING="end";
  public static final String VERB="BlackboardTestVerb";
  public static final String STATUS="STATUS";
  public static final String EXP_NAME_PREP="EXP_NAME";
  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#getPath()
   */
  protected String getPath() {
    // TODO Auto-generated method stub
    return "/testManager";
  }

  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#execute(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
   */
  protected void execute(HttpServletRequest request, HttpServletResponse response) {
    // TODO Auto-generated method stub

    String doParam = request.getParameter(DO_PARAM);
    String expParam = request.getParameter(EXP_PARAM);
    if(doParam!=null){
      blackboardService.openTransaction();
      PlanningFactory pf = (PlanningFactory)domainService.getFactory("planning");
      NewTask task = pf.newTask();
      task.setVerb(Verb.getVerb(VERB));
      Vector phrases = new Vector();
      NewPrepositionalPhrase npp = pf.newPrepositionalPhrase();
      npp.setIndirectObject(doParam);
      npp.setPreposition(STATUS);
      phrases.add(npp);
			
      NewPrepositionalPhrase expp = pf.newPrepositionalPhrase();
      expp.setPreposition(EXP_NAME_PREP);
      expp.setIndirectObject(expParam);
      phrases.add(expp);
			
      task.setPrepositionalPhrases(phrases.elements());
			
      blackboardService.publishAdd(task);
      blackboardService.closeTransaction();
			
    }
  }
}
