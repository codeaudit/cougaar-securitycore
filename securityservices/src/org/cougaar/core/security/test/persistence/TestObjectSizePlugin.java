/*
 * <copyright>
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * </copyright>
 */

package org.cougaar.core.security.test.persistence;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import java.util.*;
import java.io.Serializable;

import org.cougaar.core.security.servlet.AbstractServletComponent;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.AgentIdentificationService;

public class TestObjectSizePlugin extends AbstractServletComponent {
  int _bbObjs = 0;
  String _agent;
  int _threshold = 10000;
  List _objCache = new ArrayList();

    private final UnaryPredicate countObjPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        return true;
      }
    };

  protected String getPath() {
    return "/objectSizeTest";
  }

  public void load() {
    super.load();
    try {
      String queryInterval = System.getProperty("org.cougaar.core.security.test.queryBBInterval");
        _threshold = Integer.parseInt(System.getProperty("org.cougaar.core.security.test.queryBBThreshold"));
      if (queryInterval == null) {
        return;
      }

      if (logging.isInfoEnabled()) {
        logging.info("Start threshold to count BB objs, threshold: " + _threshold);
      }
      ThreadService threadService=(ThreadService)
        serviceBroker.getService(this,ThreadService.class, null);
      if (threadService != null) {
        AgentIdentificationService ais = (AgentIdentificationService)
          serviceBroker.getService(this, AgentIdentificationService.class, null);
        _agent = ais.getMessageAddress().toAddress();
        serviceBroker.releaseService(this, AgentIdentificationService.class, null);

        int sleepTime = Integer.parseInt(queryInterval);  

        threadService.getThread(this, new CountBBObjs()).
          schedule(0,sleepTime);
      }

    } catch (Exception ex) {
        logging.error("Exception in load :", ex);
    }
  }

  public class CountBBObjs implements Runnable {
    public void run() {
      Thread td=Thread.currentThread();
      td.setPriority(Thread.MIN_PRIORITY);
      
      _bbObjs = 0;
      blackboardService.openTransaction();
      Collection c = blackboardService.query(countObjPredicate);
      blackboardService.closeTransaction();
/*
      if (_bbObjs < _threshold) {
        return;
      }
*/
      if (logging.isInfoEnabled()) {
        logging.info("Number of Objects in " + _agent + "'s blackboard: " + c.size());
      }
    }
  }

  protected void execute(HttpServletRequest request, HttpServletResponse response) {
    if (request.getMethod().equals("GET")) {
      executeGet(request, response);
    }
    else {
      executePost(request, response);
    }
  }

  protected void executeGet(HttpServletRequest request, HttpServletResponse response) {
    try {
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
        out.println("<html>");
        out.println("<head>");
        out.println("<title>object size test </title>");
        out.println("</head>");
        out.println("<body>");
        out.println("<H2> Object type </H2>");
        out.println("<form action=\"" + request.getRequestURI() + "\" method =\"post\">");
        out.println("object type: <input name=\"type\" type=\"text\" value=\"java.lang.Integer\"><br><br>");
        out.println("count: <input name=\"count\" type=\"text\" value=\"100000\"><br><br>");
        out.println("hashtables: <input name=\"hash\" type=\"text\" value=\"0\"><br><br>");
//        out.println("publishNow: <input name=\"publish\" type=\"text\" value=\"false\"><br><br>");
        out.println("persistNow: <input name=\"persist\" type=\"text\" value=\"false\"><br><br>");
        out.println("<br><input type=\"submit\">&nbsp;&nbsp;&nbsp;");

        out.println("<input type=\"reset\">");
        out.println("</form>");
        out.println("</body></html>");
        out.flush();
        out.close();
    } catch (Exception iox) {
        logging.error("Exception in request :" + iox);
    }
  }

  protected void executePost(HttpServletRequest request, HttpServletResponse response) {
    try {
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");

      String type = request.getParameter("type");
      int count = Integer.parseInt(request.getParameter("count"));
      int hash = Integer.parseInt(request.getParameter("hash"));
      boolean doPersist = request.getParameter("persist").equals("true");
//      boolean doPublish = request.getParameter("publish").equals("true");

      int totalobj = 0;
      Class cls = Class.forName(type);
      try {
        if (count != 0) {          
//          _objCache.clear();
          if (hash == 0) { 
            for (int i = 0; i < count; i++) {
              //Object o = cls.newInstance();
              Object o = new Integer(1);
              _objCache.add(o);
              totalobj++;
            }
          }
          else {
            for (int list = 0; list < hash; list++) {
              List table = new ArrayList();
//              _objCache.add(table);
              for (int i = 0; i < count; i++) {
                Object o = new Integer(1);
                table.add(o);
                totalobj++;
              }
              blackboardService.openTransaction();
              blackboardService.publishAdd(table);
              blackboardService.closeTransaction();
            }
          }
          if (logging.isInfoEnabled()) {
            logging.info("total of " + totalobj + " generated");
          }
        }
/*
        else if (doPublish) {
          blackboardService.openTransaction();
          Iterator it = _objCache.iterator();
          while (it.hasNext()) {
            blackboardService.publishAdd(it.next());
          }
          if (logging.isInfoEnabled()) {
            logging.info("total of " + _objCache.size() + " published");
          }
          blackboardService.closeTransaction();
        }
*/
        else if (doPersist) { 
          blackboardService.persistNow();
          if (logging.isInfoEnabled()) {
            logging.info("total of " + _objCache.size() + " persisted");
          }
        }

      } catch (Exception ex) {
        logging.error("Exception ", ex);
      }

      out.println("</html>");
      out.flush();
      out.close();
    } catch (Exception iox) {
        logging.error("Exception in response :", iox);
    }  
  }

}
