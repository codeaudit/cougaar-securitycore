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
//        return (o instanceof BlackboardTestObject);
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
        serviceBroker.releaseService(this, AgentIdentificationService.class, ais);

        int sleepTime = Integer.parseInt(queryInterval);  

        threadService.getThread(this, new CountBBObjs()).
          schedule(0,sleepTime);
        serviceBroker.releaseService(this, ThreadService.class, threadService);

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


      Hashtable pathList = new Hashtable();
      Iterator it = c.iterator();
      while (it.hasNext()) {
        String cls = it.next().getClass().getName();
        PathIndex index = (PathIndex)pathList.get(cls);
        if (index == null) {
          pathList.put(cls, new PathIndex(cls));
        }
        else {
          index.occurance++;
        }
      }
         
      if (logging.isInfoEnabled()) {
        logging.info("Number of Objects in " + _agent + "'s blackboard: " + c.size());
        int total = 0;
        for (Enumeration en = pathList.elements(); en.hasMoreElements() && total < 50; total++) {
          PathIndex index = (PathIndex)en.nextElement();
          logging.info(index._cls + " => " + index.occurance);
        }
      }
    }
  }

  class PathIndex {
    String _cls;
    int occurance = 1;

    PathIndex(String cls) {
      _cls = cls;
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
        out.println("count: <input name=\"count\" type=\"text\" value=\"100,1000,10000,100000\"><br><br>");
        out.println("list: <input name=\"list\" type=\"text\" value=\"100,1000,3000,5000\"><br><br>");
        out.println("persistTime: <input name=\"persist\" type=\"text\" value=\"2\">m<br><br>");
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
      String countString = request.getParameter("count");
      String listString = request.getParameter("list");
      int persistTime = Integer.parseInt(request.getParameter("persist")) * 60000;
      ThreadService threadService=(ThreadService)
        serviceBroker.getService(this,ThreadService.class, null);
      if (threadService != null) {
        threadService.getThread(this, new PublishTest(countString, listString, persistTime)).
          schedule(0,1);
        serviceBroker.releaseService(this, ThreadService.class, threadService);
      }

      out.println("</html>");
      out.flush();
      out.close();
    } catch (Exception iox) {
        logging.error("Exception in response :", iox);
    }  
  }

  private class PublishTest implements Runnable {
    String countString;
    String listString;
    int persistTime;
    PublishTest(String cs, String ls, int pt) {
      countString = cs;
      listString = ls;
      persistTime = pt;
    }

    public void run() {
      try {
      List countList = getListFromString(countString);
      List listList = getListFromString(listString);
        Iterator ilist = listList.iterator();
        while (ilist.hasNext()) {
          int lsize = ((Integer)ilist.next()).intValue();
          int csize;
          Iterator iCount = countList.iterator();
          while (iCount.hasNext()) {
            if (logging.isInfoEnabled()) {
              logging.info("waiting " + persistTime + " before publishing");
            }

            csize = ((Integer)iCount.next()).intValue();
            publishList(lsize, csize);

            Thread.currentThread().sleep(persistTime);
            blackboardService.persistNow();
            if (logging.isInfoEnabled()) {
              logging.info("total of " + lsize + " of size " + csize + " persisted");
            }

          }
        }
      } catch (Exception ex) {
        logging.error("Exception ", ex);
      }
    }
  }

  private List getListFromString(String str) throws Exception {
    List l = new ArrayList();
    int start = 0;
    int index = 0;
    while (index != -1) {
      index = str.indexOf(',', start);
      if (index == -1) {
        break;
      }
      l.add(new Integer(Integer.parseInt(str.substring(start, index))));
      start = index + 1;
    }
    l.add(new Integer(Integer.parseInt(str.substring(start, str.length()))));
    return l;
  }

  private void publishList(int lsize, int csize) {
    int total = 0;
        for (int i = 0; i < lsize; i++) {
          List table = new BlackboardTestObject();

          for (int count = 0; count < csize; count++) {
            Object o = new Integer(count);
            table.add(o);
          }
          blackboardService.openTransaction();
          blackboardService.publishAdd(table);
          total++;
          blackboardService.closeTransaction();
        }
          if (logging.isInfoEnabled()) {
            logging.info("total of " + lsize + " of size " + csize + " generated, " + total + " published.");
          }
  }
}
