/*
 * <copyright>
 *  Copyright 1997-2001 Network Associates
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */
package org.cougaar.core.security.test;

import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.*;
import java.lang.reflect.*;
import java.security.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.servlet.*;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.core.util.*;
import org.cougaar.planning.ldm.asset.*;
import org.cougaar.planning.ldm.measure.AbstractMeasure;
import org.cougaar.planning.ldm.plan.*;
import org.cougaar.util.*;
import org.cougaar.planning.servlet.*;
import org.cougaar.core.service.*;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.WhitePagesService;

import org.apache.xerces.dom.DocumentImpl;
import org.apache.xml.serialize.XMLSerializer;
import org.apache.xml.serialize.OutputFormat;
import org.cougaar.core.blackboard.BlackboardClient;

import org.cougaar.core.security.certauthority.SecurityServletSupport;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.jasper.compiler.*;
import org.cougaar.core.security.test.MessageInterceptorAspect.*;

/**
 * <p>This code was ripped off of the PlanViewServlet. I didn't want to modify
 * the PlanViewServlet so that I could override the private functions, so
 * I just copied the code. Not good style, but quick and easy.</p>
 * <p>in order to get this to run: </p>
 * <ul>
 * <li>copy the <code>jasper-compiler.jar</code> from
 *     <code>securityservices/build/jasper/lib</code> to $CIP/sys</li>
 * <li>sign the jasper-compiler.jar with the privileged signature</li>
 * <li>add the following permissions to the Cougaar_Java.policy for
 *     <code>securityservices.jar</code>:<br>
 * <pre>        permission java.io.FilePermission "${/}usr${/}java${/}*", "read";
 *      permission java.io.FilePermission "${/}usr${/}java${/}-", "read";
 *      permission java.io.FilePermission "${/}usr${/}java${/}", "read";
 *      permission java.lang.RuntimePermission "accessClassInPackage.sun.tools.javac";</pre>
 *
 *   </li>
 * <li>Add the following line to the Node .ini file:<br>
 * <pre>Node.AgentManager.Agent.MessageTransport.Aspect(INTERNAL) = org.cougaar.core.security.test.MessageInterceptorAspect</pre>
 * </li>
 * </ul>
 */
public class EditObjectServlet extends HttpServlet {

  private SecurityServletSupport support;
  
  public EditObjectServlet(SecurityServletSupport support) {
    this.support = support;
  }

  public void doGet(
      HttpServletRequest request,
      HttpServletResponse response) throws IOException, ServletException
  {
    // create a new "PlanViewer" context per request
    PlanViewer pv = new PlanViewer(support);
    pv.execute(request, response);  
  }

  public void doPost(
      HttpServletRequest request,
      HttpServletResponse response) throws IOException, ServletException
  {
    // create a new "PlanViewer" context per request
    PlanViewer pv = new PlanViewer(support);
    pv.execute(request, response);  
  }

  /**
   * This inner class does all the work.
   * <p>
   * A new class is created per request, to keep all the
   * instance fields separate.  If there was only one
   * instance then multiple simultaneous requests would
   * corrupt the instance fields (e.g. the "out" stream).
   * <p>
   * This acts as a <b>context</b> per request.
   */
  private static class PlanViewer implements BlackboardClient {

    // some constants:
    private static final String PREDS_FILENAME_PROPERTY =
      "org.cougaar.planning.servlet.planview.preds";
    private static final String DEFAULT_PREDS_FILENAME = 
      "default.preds.dat";
    private static final boolean DEBUG = false;
    private static final int DEFAULT_LIMIT = 100;

    //
    // parameters from the URL:
    //

    /**
     * "mode" constants, which control which page to generate.
     */
    public static final String MODE = "mode";
    public static final int MODE_FRAME                        =  0;
    public static final int MODE_ALL_TASKS                    =  1;
    public static final int MODE_CLUSTERS                     =  2;
    public static final int MODE_TASK_DETAILS                 =  3;
    public static final int MODE_TASKS_SUMMARY                =  4;
    public static final int MODE_PLAN_ELEMENT_DETAILS         =  5;
    public static final int MODE_ALL_PLAN_ELEMENTS            =  6;
    public static final int MODE_ASSET_DETAILS                =  7;
    public static final int MODE_ALL_ASSETS                   =  8;
    public static final int MODE_SEARCH                       =  9;
    public static final int MODE_XML_HTML_DETAILS             = 10;
    public static final int MODE_XML_RAW_DETAILS              = 11;
    public static final int MODE_ALL_UNIQUE_OBJECTS           = 12;
    public static final int MODE_WELCOME                      = 13;
    public static final int MODE_WELCOME_DETAILS              = 14;
    public static final int MODE_TASK_DIRECT_OBJECT_DETAILS   = 15;
    public static final int MODE_ASSET_TRANSFER_ASSET_DETAILS = 16;
    public static final int MODE_XML_HTML_ATTACHED_DETAILS    = 17;
    public static final int MODE_XML_RAW_ATTACHED_DETAILS     = 18;
    public static final int MODE_ADVANCED_SEARCH_FORM         = 19;
    public static final int MODE_ADVANCED_SEARCH_RESULTS      = 20;
    public static final int MODE_EDIT_FIELDS                  = 21;
    public static final int MODE_ENTER_CODE                   = 22;
    public static final int MODE_EXEC_EDITS                   = 23;
    public static final int MODE_LOAD_SAVE_OBJECT             = 24;
    public static final int MODE_EXECUTE_CODE                 = 25;
    public static final int MODE_DEL_MSG_MOD                  = 26;
    public static final int MODE_ALL_MSG_MODS                 = 27;
    public static final int MODE_ENTER_MSG_MOD                = 28;
    public static final int MODE_SAVE_MSG_MOD                 = 29;

    private int mode = -1;

    // filter by uid
    public static final String ITEM_UID = "uid";
    private String itemUID;

    // filter by task verb
    public static final String VERB = "verb";
    private String verbFilter;

    // limit quantity of data
    public static final String LIMIT = "limit";
    private boolean limit;

    // predicate
    public static final String PREDICATE = "pred";
    private String pred;

    // predicate style
    public static final String PREDICATE_STYLE = "predStyle";
    private String predStyle;

    // view parsed predicate for debugging
    public static final String PREDICATE_DEBUG = "predDebug";
    private boolean predDebug;

    // sort results by UID
    public static final String SORT_BY_UID = "sortByUID";
    private boolean sortByUID; 

    // writer from the request
    private PrintWriter out;

    private HashMap fields = new HashMap();
    private HashMap methods = new HashMap();
    private String  file;
    private HttpServletResponse response;

    public static final String CODE = "code";
    public static final String IMPORTS = "imports";
    public static final String MIDDLE  = "middle";
    public static final String MOD_NAME  = "modName";
    public static final String PUBLISH_CHANGE = "pc";
    public static final String CODE_PACKAGE =
      "package tmp;\n";
    public static final String CODE_CLASS_TOP = 
      "public final class TmpEditObject {\n";
    public static final String CODE_MSG_TOP = 
      "public final class TmpEditObject\n  implements org.cougaar.core.security.test.MessageInterceptorAspect.SendQueueInterceptor {\n";
    public static final String CODE_METHOD_SIG =
      "  public static final void execute(Object obj) {\n";
    public static final String CODE_MSG_SIG = 
      "  public final boolean execute(AttributedMessage msg) {\n";
    public static final String CODE_CLASS_BOTTOM = 
      "  }\n" +
      "}\n";

    private String code;
    private String imports;
    private String middle;
    private String msgName;
    private boolean publishChange;
    
    // since "PlanViewer" is a static inner class, here
    // we hold onto the support API.
    //
    // this makes it clear that PlanViewer only uses
    // the "support" from the outer class.
    private SecurityServletSupport support;

    public PlanViewer(SecurityServletSupport support) {
      this.support = support;
    }

    public long currentTimeMillis() { return System.currentTimeMillis(); }

    public String getBlackboardClientName() { return "EditObjectServlet"; }
    
    public boolean triggerEvent(Object event) { return false; }
    /**
     * Main method.
     */
    public void execute(
        HttpServletRequest request, 
        HttpServletResponse response) throws IOException, ServletException 
    {
      this.out = response.getWriter();
      this.response = response;

      // create a URL parameter visitor
      ServletUtil.ParamVisitor vis = 
        new ServletUtil.ParamVisitor() {
          public void setParam(String name, String value) {
            if (name.equalsIgnoreCase(MODE)) {
              try {
                mode = Integer.parseInt(value);
              } catch (Exception eBadNumber) {
                System.err.println("INVALID MODE: "+value);
                mode = MODE_FRAME;
              }
            } else if (name.equalsIgnoreCase(ITEM_UID)) {
              if (value != null) {
                try {
                  itemUID = URLDecoder.decode(value, "UTF-8");
                } catch (Exception eBadEnc) {
                  System.err.println("INVALID UID: "+value);
                }
              }
            } else if (name.equalsIgnoreCase(VERB)) {
              verbFilter = value;
            } else if (name.equalsIgnoreCase(LIMIT)) {
              limit = "true".equalsIgnoreCase(value);
            } else if (name.equalsIgnoreCase(PREDICATE)) {
              pred = value;
            } else if (name.equalsIgnoreCase(PREDICATE_STYLE)) {
              predStyle = value;
            } else if (name.equalsIgnoreCase(PREDICATE_DEBUG)) {
              predDebug = 
                ((value != null) ?  
                 value.equalsIgnoreCase("true") : 
                 true);
            } else if (name.equalsIgnoreCase(SORT_BY_UID)) {
	      sortByUID = 
		((value != null) ?  
                 value.equalsIgnoreCase("true") : 
                 true);
	    } else if (name.startsWith("field-")) { 
              fields.put(name.substring(6),value);
	    } else if (name.startsWith("method-")) { 
              methods.put(name.substring(6),value);
            } else if ("file".equals(name)) {
              file = value; 
            } else if (IMPORTS.equals(name)) {
              imports = value;
            } else if (MIDDLE.equals(name)) {
              middle = value;
            } else if (CODE.equals(name)) {
              code = value; 
            } else if (MOD_NAME.equals(name)) {
              msgName = value; 
            } else if (PUBLISH_CHANGE.equals(name)) {
              publishChange = true;
            } 
          }
        };

      // visit the URL parameters
      ServletUtil.parseParams(vis, request);

      try {
        // decide which page to generate
        switch (mode) {
          default:
            if (DEBUG) {
              System.err.println("DEFAULT MODE");
            }
          case MODE_FRAME:
            displayFrame();
            break;
          case MODE_WELCOME:
            displayWelcome();
            break;
          case MODE_WELCOME_DETAILS:
            displayWelcomeDetails();
            break;
          case MODE_ALL_TASKS:
            displayAllTasks();
            break;
          case MODE_TASK_DETAILS:
            displayTaskDetails();
            break;
          case MODE_TASKS_SUMMARY:
            displayTasksSummary();
            break;
          case MODE_PLAN_ELEMENT_DETAILS:
            displayPlanElementDetails();
            break;
          case MODE_ALL_PLAN_ELEMENTS:
            displayAllPlanElements();
            break;
          case MODE_ASSET_DETAILS:
          case MODE_TASK_DIRECT_OBJECT_DETAILS:
          case MODE_ASSET_TRANSFER_ASSET_DETAILS:
            displayAssetDetails();
            break;
          case MODE_ALL_ASSETS:
            displayAllAssets();
            break;
          case MODE_CLUSTERS:
          case MODE_SEARCH:
            displaySearch();
            break;
          case MODE_XML_HTML_DETAILS:
          case MODE_XML_HTML_ATTACHED_DETAILS:
          case MODE_XML_RAW_DETAILS:
          case MODE_XML_RAW_ATTACHED_DETAILS:
            displayUniqueObjectDetails();
            break;
          case MODE_ALL_UNIQUE_OBJECTS:
            displayAllUniqueObjects();
            break;
          case MODE_ADVANCED_SEARCH_FORM:
            displayAdvancedSearchForm();
            break;
          case MODE_ADVANCED_SEARCH_RESULTS:
            displayAdvancedSearchResults();
            break;
            
        case MODE_EDIT_FIELDS:
          displayEditFields();
          break;
        case MODE_ENTER_CODE:
          displayCodeForm();
          break;
        case MODE_EXEC_EDITS:
          editFields();
          break;
          
        case MODE_LOAD_SAVE_OBJECT:
          loadSaveObject();
          break;
          
        case MODE_EXECUTE_CODE:
          runCode();
          break;

        case MODE_DEL_MSG_MOD:
          delMsgMod();
          break;
        case MODE_ALL_MSG_MODS:
          displayAllMsgMods();
          break;
        case MODE_ENTER_MSG_MOD:
          displayMsgModForm();
          break;
        case MODE_SAVE_MSG_MOD:
          saveMsgMod();
          break;
        }
      } catch (Exception e) {
        System.err.println(
            "/$"+
            support.getEncodedAgentName()+
            support.getPath()+
            " Exception: ");
        e.printStackTrace();
        out.print(
            "<html><body><h1>"+
            "<font color=red>Unexpected Exception!</font>"+
            "</h1><p><pre>");
        e.printStackTrace(out);
        out.print("</pre></body></html>");
        out.flush();
      }
    }

    /** BEGIN DISPLAY ROUTINES **/

    /**
     * displayFrame.
     */
    private void displayFrame()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Frame");
      }
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>"+
          "Cougaar PlanViewer"+
          "</title>\n"+
          "</head>\n"+
          "<frameset cols=\"25%,75%\">\n"+
          "<frameset rows=\"32%,68%\">\n"+
          "<frame src=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());     
      out.print(
          "?"+
          MODE+
          "="+
          MODE_SEARCH+
          "\" name=\"searchFrame\">\n");
      //
      // Show blank WelcomeDetails page in itemFrame, since user
      // probably didn't specify $encodedAgentName in URL.
      //
      out.print("<frame src=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print(
          "?"+
          MODE+
          "="+
          MODE_WELCOME_DETAILS+
          "\" name=\"itemFrame\">\n"+
          "</frameset>\n"+
          "<frame src=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      // 
      // Show blank Welcome page in tablesFrame, since user
      // probably didn't specify $encodedAgentName in URL.
      //
      out.print(
          "?"+
          MODE+
          "="+
          MODE_WELCOME+
          "\" name=\"tablesFrame\">\n"+
          "</frameset>\n"+
          "<noframes>\n"+
          "<h2>Frame Task</h2>\n"+
          "<p>"+
          "This document is designed to be viewed using the frames feature. "+
          "If you see this message, you are using a non-frame-capable web "+
          "client.\n"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayWelcome.
     */
    private void displayWelcome()
    {
      if (DEBUG) {
        System.out.println("Display Welcome");
      }
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>"+
          "COUGAAR PlanView"+
          "</title>\n"+
          "</head>\n"+
          "<body ");
      out.print(
          "bgcolor=\"#F0F0F0\">\n"+
          "<p>"+
          "<font size=small color=mediumblue>No Agent selected.</font>\n"+
          "</body>\n"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayWelcomeDetails.
     */
    private void displayWelcomeDetails()
    {
      if (DEBUG) {
        System.out.println("Display Welcome Details");
      }
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>"+
          "Item Details View"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<p>"+
          "<font size=small color=mediumblue>No Item selected.</font>\n"+
          "</body>\n"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayTaskDetails.
     */
    private void displayTaskDetails()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Task Details");
      }
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>"+
          "Children Task View"+
          "</title>"+
          "</head>\n"+
          "<body  bgcolor=\"#F0F0F0\">\n"+
          "<b>");
      // link to cluster
      printLinkToTasksSummary();
      out.print(
          "</b><br>\n"+
          "Task<br>");
      // find task
      UniqueObject baseObj = 
        findUniqueObjectWithUID(itemUID);
      if (baseObj instanceof Task) {
        printTaskDetails((Task)baseObj);
      } else {
        out.print(
            "<p>"+
            "<font size=small color=mediumblue>");
        if (itemUID == null) {
          out.print("No Task selected.");
        } else if (baseObj == null) {
          out.print("No Task matching \"");
          out.print(itemUID);
          out.print("\" found.");
        } else {
          out.print("UniqueObject with UID \"");
          out.print(itemUID);
          out.print("\" is not a Task: ");
          out.print(baseObj.getClass().getName());
        }
        out.print(
            "</font>"+
            "<p>\n");
      }
      out.print(
          "</body>\n"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayAllTasks.
     */
    private void displayAllTasks()
    {
      if (DEBUG) {
        System.out.println("\nDisplay All Tasks");
      }
      // find tasks
      Collection col;
      if (verbFilter != null) {
        col = findTasksWithVerb(verbFilter);
      } else {
        col = findAllTasks();
      }
      int numTasks = col.size();
      Iterator tasksIter = col.iterator();
      if (DEBUG) {
        System.out.println("Fetched Tasks");
      }
      // begin page
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " Tasks"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<p>"+
          "<center>");
      if (limit && (numTasks > DEFAULT_LIMIT)) {
        out.print("Showing first <b>");
        out.print(DEFAULT_LIMIT);
        out.print("</b> of ");
      }
      out.print("<b>");
      out.print(numTasks);
      out.print(
          "</b> Task");
      if (numTasks != 1) {
        out.print("s");
      }
      if (verbFilter != null) {
        out.print(" with verb ");
        out.print(verbFilter);
      }
      out.print(" at ");
      out.print(support.getEncodedAgentName());
      out.print("</center>\n");
      if (limit && (numTasks > DEFAULT_LIMIT)) {
        out.print("<center>");
        // link to all tasks.
        printLinkToAllTasks(
            verbFilter, 0, numTasks, true);
        out.print("</center>\n");
      }
      // print table headers
      out.print(
          "\n<table align=center border=1 cellpadding=1\n"+
          " cellspacing=1 width=75%\n"+
          " bordercolordark=#660000 bordercolorlight=#cc9966>\n"+
          "<tr>\n"+
          "<td colspan=7>"+
          "<font size=+1 color=mediumblue><b>Tasks</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td rowspan=2><font color=mediumblue><b>UID</b></font></td>\n"+
          "<td rowspan=2><font color=mediumblue><b>Verb</b></font></td>\n"+
          "<td colspan=4>"+
          "<font color=mediumblue><b>Direct Object</b></font>"+
          "</td>\n"+
          "<td rowspan=2>"+
          "<font color=mediumblue><b>Prepositional Phrases</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td><font color=mediumblue><b>UID</b></font></td>\n"+
          "<td><font color=mediumblue><b>TypeID</b></font></td>\n"+
        "<td><font color=mediumblue><b>ItemID</b></font></td>\n"+
        "<td><font color=mediumblue><b>Quantity</b></font></td>\n"+
        "</tr>\n");
      if (numTasks > 0) {
        // print table rows
        int rows = 0;
        while (tasksIter.hasNext()) {
          Task task = (Task)tasksIter.next();
          out.print(
              "<tr>\n"+
              "<td>\n");
          printLinkToLocalTask(task);
          out.print(
              "</td>\n"+
              "<td>\n");
          // show verb
          Verb v = task.getVerb();
          if (v != null) {
            out.print(v.toString());
          } else {
            out.print("<font color=red>missing verb</font>");
          }
          out.print("</td>\n");
          // show direct object
          printTaskDirectObjectTableRow(task);
          // show prepositional phrases
          out.print(
              "<td>"+
              "<font size=-1>");
          Enumeration enprep = task.getPrepositionalPhrases();
          while (enprep.hasMoreElements()) {
            PrepositionalPhrase pp = 
              (PrepositionalPhrase)enprep.nextElement();
            String prep = pp.getPreposition();
            out.print("<font color=mediumblue>");
            out.print(prep);
            out.print("</font>");
            printObject(pp.getIndirectObject());
            out.print(",");
          }
          out.print(
              "</font>"+
              "</td>\n"+
              "</tr>\n");
          if ((++rows % DEFAULT_LIMIT) == 0) {
            if (limit) {
              // limit to DEFAULT_LIMIT
              break;
            }
            // restart table
            out.print("</table>\n");
            out.flush();
            out.print(
                "<table align=center border=1 cellpadding=1\n"+
                " cellspacing=1 width=75%\n"+
                " bordercolordark=#660000 bordercolorlight=#cc9966>\n");
          }
        }
        // end table
        out.print("</table>\n");
        if (limit && (rows == DEFAULT_LIMIT)) {
          // link to unlimited view
          out.print(
              "<p>"+
              "<center>");
          printLinkToAllTasks(
              verbFilter, 0, numTasks, true);
          out.print(
              "<br>"+
              "</center>\n");
        }
      } else {
        // end table
        out.print(
            "</table>\n"+
            "<center>"+
            "<font color=mediumblue>\n"+
            "No Tasks");
        if (verbFilter != null) {
          out.print(" with verb ");
          out.print(verbFilter);
        }
        out.print(" found in ");
        out.print(support.getEncodedAgentName());
        out.print(
            "\n...try again"+
            "</font>"+
            "</center>\n");
      }
      // end page
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayTaskSummary.
     */
    private void displayTasksSummary()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Tasks Summary");
      }
      // find tasks
      boolean oldSortByUID = sortByUID;
      sortByUID = false;
      Collection col = findAllTasks();
      sortByUID = oldSortByUID;
      int numTasks = col.size();
      Iterator tasksIter = col.iterator();
      if (DEBUG) {
        System.out.println("Fetched Tasks");
      }
      // begin page
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " Tasks Summary"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<center>");
      printLinkToAllTasks(
          null, 0, numTasks, false);
      out.print("</center>\n");
      if (numTasks > DEFAULT_LIMIT) {
        // give limit option
        out.print("<center>");
        printLinkToAllTasks(
            null, DEFAULT_LIMIT, numTasks, false);
        out.print("</center>\n");
      }
      // begin table
      out.print(
          "<p>\n"+
          "<table align=center border=1 cellpadding=1 cellspacing=1\n"+
          " width=75% bordercolordark=#660000 bordercolorlight=#cc9966>\n"+
          "<tr>\n"+
          "<td colspan=2>"+
          "<font size=+1 color=mediumblue><b>Tasks Summary</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td><font color=mediumblue><b>Verb</font></b></td>\n"+
          "<td><font color=mediumblue><b>Count</font></b></td>\n"+
          "</tr>\n");
      // table rows
      if (numTasks != 0) {
        // count by verb
        HashMap tasksInfoMap = new HashMap();
        while (tasksIter.hasNext()) {
          Task task = (Task)tasksIter.next();
          Verb verb = task.getVerb();
          VerbSummaryInfo info = 
            (VerbSummaryInfo)tasksInfoMap.get(verb);
          if (info == null) {
            info = new VerbSummaryInfo(verb);
            tasksInfoMap.put(verb, info);
          }
          ++info.counter;
        }
        // sort by verb
        Collection sortedInfosCol =
          Sortings.sort(
              tasksInfoMap.values(),
              SummaryInfo.LARGEST_COUNTER_FIRST_ORDER);
        Iterator sortedInfosIter = sortedInfosCol.iterator();
        // print rows
        while (sortedInfosIter.hasNext()) {
          VerbSummaryInfo info = (VerbSummaryInfo)sortedInfosIter.next();
          out.print(
              "<tr>\n"+
              "<td>\n");
          // link to all tasks with verb
          printLinkToAllTasks(
              info.verb.toString(), 0, info.counter, false);
          if (info.counter > DEFAULT_LIMIT) {
            // link to limited number of tasks with verb
            out.print(" (");
            printLinkToAllTasks(
                info.verb.toString(), DEFAULT_LIMIT, info.counter, false);
            out.print(")");
          }
          out.print(
              "</td>\n"+
              "<td align=right>");
          out.print(info.counter);
          out.print(
              "</td>\n"+
              "</tr>\n");
        }
      }
      // end table
      out.print("</table>\n");
      if (numTasks == 0) {
        out.print(
            "<center>"+
            "<font color=mediumblue >\n"+
            "No Tasks found in ");
        out.print(support.getEncodedAgentName());
        out.print(
            "\n...try again"+
            "</font>"+
            "</center>\n");
      }
      // end page
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /**
    /**
     * displayPlanElementDetails.
     */
    private void displayPlanElementDetails()
    {
      if (DEBUG) {
        System.out.println("\nDisplay PlanElement Details");
      }
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>"+
          "PlanElement View"+
          "</title>"+
          "</head>\n"+
          "<body  bgcolor=\"#F0F0F0\">\n"+
          "<b>");
      // link to cluster
      printLinkToTasksSummary();
      out.print(
          "</b><br>\n");
      // find plan element
      UniqueObject baseObj = 
        findUniqueObjectWithUID(itemUID);
      if (baseObj instanceof PlanElement) {
        printPlanElementDetails((PlanElement)baseObj);
      } else {
        out.print(
            "<p>"+
            "<font size=small color=mediumblue>");
        if (itemUID == null) {
          out.print("No PlanElement selected.");
        } else if (baseObj == null) {
          out.print("No PlanElement matching \"");
          out.print(itemUID);
          out.print("\" found.");
        } else {
          out.print("UniqueObject with UID \"");
          out.print(itemUID);
          out.print("\" is not a PlanElement: ");
          out.print(baseObj.getClass().getName());
        }
        out.print(
            "</font>"+
            "<p>\n");
      }
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayAllPlanElements.
     */
    private void displayAllPlanElements()
    {
      if (DEBUG) {
        System.out.println("\nDisplay All PlanElements");
      }
      Collection col = findAllPlanElements();
      int numPlanElements = col.size();
      Iterator peIter = col.iterator();
      if (DEBUG) {
        System.out.println("Fetched PlanElements");
      }
      // begin page
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " PlanElements"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<center>");
      if (limit && (numPlanElements > DEFAULT_LIMIT)) {
        out.print("Showing first <b>");
        out.print(DEFAULT_LIMIT);
        out.print("</b> of ");
      }
      out.print("<b>");
      out.print(numPlanElements);
      out.print(
          "</b> PlanElement");
      if (numPlanElements != 1) {
        out.print("s");
      }
      out.print(" at ");
      out.print(support.getEncodedAgentName());
      out.print("</center>");
      if (limit && (numPlanElements > DEFAULT_LIMIT)) {
        out.print("<center>");
        // link to all pes
        printLinkToAllPlanElements(
            0, numPlanElements, false);
        out.print("</center>");
      }
      out.print(
          "\n<table align=center border=1 cellpadding=1\n"+
          " cellspacing=1 width=75%\n"+
          " bordercolordark=#660000 bordercolorlight=#cc9966>\n"+
          "<tr>\n"+
          "<td colspan=2>"+
          "<font size=+1 color=mediumblue><b>PlanElements</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td><font color=mediumblue><b>UID</b></font></td>\n"+
          "<td><font color=mediumblue><b>Type</b></font></td>\n"+
          "</tr>\n");
      if (numPlanElements > 0) {
        // print table rows
        int rows = 0;
        while (peIter.hasNext()) {
          PlanElement pe = (PlanElement)peIter.next();
          out.print(
              "<tr>\n"+
              "<td>\n");
          printLinkToPlanElement(pe);
          out.print(
              "</td>\n"+
              "<td>\n");
          int peType = getItemType(pe);
          if (peType != ITEM_TYPE_OTHER) {
            out.print(ITEM_TYPE_NAMES[peType]);
          } else {
            out.print("<font color=red>");
            if (pe != null) {
              out.print(pe.getClass().getName());
            } else {
              out.print("null");
            }
            out.print("</font>");
          }
          out.print(
              "</td>"+
              "</tr>\n");
          if ((++rows % DEFAULT_LIMIT) == 0) {
            if (limit) {
              // limit to DEFAULT_LIMIT
              break;
            }
            // restart table
            out.print("</table>\n");
            out.flush();
            out.print(
                "<table align=center border=1 cellpadding=1\n"+
                " cellspacing=1 width=75%\n"+
                " bordercolordark=#660000 bordercolorlight=#cc9966>\n");
          }
        }
        // end table
        out.print("</table>\n");
        if (limit && (rows == DEFAULT_LIMIT)) {
          // link to unlimited view
          out.print(
              "<p>"+
              "<center>");
          printLinkToAllPlanElements(
              0, numPlanElements, false);
          out.print(
              "<br>"+
              "</center>\n");
        }
      } else {
        out.print(
            "</table>"+
            "<center>"+
            "<font color=mediumblue>\n"+
            "No PlanElements found in ");
        out.print(support.getEncodedAgentName());
        out.print(
            "\n...try again"+
            "</font>"+
            "</center>\n");
      }
      // end page
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayAssetDetails.
     */
    private void displayAssetDetails()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Asset Details");
      }
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>"+
          "Asset View"+
          "</title>"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<b>");
      // link to cluster
      printLinkToTasksSummary();
      out.print(
          "</b><br>\n"+
          "Asset<br>");
      // find "base" UniqueObject with the specifed UID
      UniqueObject baseObj = 
        findUniqueObjectWithUID(itemUID);
      Asset asset = null;
      // get asset
      switch (mode) {
        case MODE_ASSET_DETAILS:
          // asset itself
          if (baseObj instanceof Asset) {
            asset = (Asset)baseObj;
          }
          break;
        case MODE_TASK_DIRECT_OBJECT_DETAILS:
          // asset attached to Task
          if (baseObj instanceof Task) {
            asset = ((Task)baseObj).getDirectObject();
          }
          break;
        case MODE_ASSET_TRANSFER_ASSET_DETAILS:
          // asset attached to AssetTransfer
          if (baseObj instanceof AssetTransfer) {
            asset = ((AssetTransfer)baseObj).getAsset();
          }
          break;
        default:
          break;
      }
      if (asset != null) {
        printAssetDetails(baseObj, asset);
      } else {
        String baseType;
        switch (mode) {
          case MODE_ASSET_DETAILS:
            baseType = "Asset";
            break;
          case MODE_TASK_DIRECT_OBJECT_DETAILS:
            baseType = "Task";
            break;
          case MODE_ASSET_TRANSFER_ASSET_DETAILS:
            baseType = "AssetTransfer";
            break;
          default:
            baseType = "<font color=red>Error</font>";
            break;
        }
        out.print(
            "<p>"+
            "<font size=small color=mediumblue>");
        if (itemUID == null) {
          out.print("No ");
          out.print(baseType);
          out.print(" selected.");
        } else if (baseObj == null) {
          out.print("No ");
          out.print(baseType);
          out.print(" matching \"");
          out.print(itemUID);
          out.print("\" found in ");
          out.print(support.getEncodedAgentName());
          out.print(".");
        } else {
          out.print("UniqueObject with UID \"");
          out.print(itemUID);
          out.print("\" is not of type ");
          out.print(baseType);
          out.print(": ");
          out.print(baseObj.getClass().getName());
        }
        out.print(
            "</font>"+
            "<p>\n");
      }
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /**
     * displayAllAssets.
     */
    private void displayAllAssets()
    {
      if (DEBUG) {
        System.out.println("\nDisplay All Assets");
      }
      Collection col = findAllAssets();
      int numAssets = col.size();
      Iterator assetIter = col.iterator();
      if (DEBUG) {
        System.out.println("Fetched Assets");
      }
      // begin page
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " Assets"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<center>");
      if (limit && (numAssets > DEFAULT_LIMIT)) {
        out.print("Showing first <b>");
        out.print(DEFAULT_LIMIT);
        out.print("</b> of ");
      }
      out.print("<b>");
      out.print(numAssets);
      out.print(
          "</b> Asset");
      if (numAssets != 1) {
        out.print("s");
      }
      out.print(" at ");
      out.print(support.getEncodedAgentName());
      out.print("</center>");
      if (limit && (numAssets > DEFAULT_LIMIT)) {
        out.print("<center>");
        // link to all assets
        printLinkToAllAssets(
            0, numAssets, false);
        out.print("</center>");
      }
      out.print(
          "\n<table align=center border=1 cellpadding=1\n"+
          " cellspacing=1 width=75%\n"+
          " bordercolordark=#660000 bordercolorlight=#cc9966>\n"+
          "<tr>\n"+
          "<td colspan=4>"+
          "<font size=+1 color=mediumblue><b>Assets</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td><font color=mediumblue><b>UID</font></b></td>\n"+
          "<td><font color=mediumblue><b>TypeID</font></b></td>\n"+
          "<td><font color=mediumblue><b>ItemID</font></b></td>\n"+
          "<td><font color=mediumblue><b>Quantity</font></b></td>\n"+
          "</tr>\n");
      if (numAssets > 0) {
        // print table rows
        int rows = 0;
        while (assetIter.hasNext()) {
          Asset asset = (Asset)assetIter.next();
          out.print("<tr>\n");
          printAssetTableRow(asset);
          out.print("</tr>\n");
          if ((++rows % DEFAULT_LIMIT) == 0) {
            // restart table
            if (limit) {
              // limit to DEFAULT_LIMIT
              break;
            }
            out.print("</table>\n");
            out.flush();
            out.print(
                "<table align=center border=1 cellpadding=1\n"+
                " cellspacing=1 width=75%\n"+
                " bordercolordark=#660000 bordercolorlight=#cc9966>\n");
          }
        }
        // end table
        out.print("</table>\n");
        if (limit && (rows == DEFAULT_LIMIT)) {
          // link to unlimited view
          out.print(
              "<p>"+
              "<center>");
          printLinkToAllAssets(
              0, numAssets, false);
          out.print(
              "<br>"+
              "</center>\n");
        }
      } else {
        out.print(
            "</table>"+
            "<center>"+
            "<font color=mediumblue>\n"+
            "No Assets found in ");
        out.print(support.getEncodedAgentName());
        out.print(
            "\n...try again"+
            "</font>"+
            "</center>\n");
      }
      // end page
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /**
     * displaySearch.
     * <p>
     * Uses JavaScript to set the FORM action, since the user selects
     * the cluster _after_ page load and the action must point to the
     * correct Agent's URL.
     */
    private void displaySearch()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Form");
      }
      out.print(
          "<html>\n"+
          "<script language=\"JavaScript\">\n"+
          "<!--\n"+
          "function mySubmit() {\n"+
          "  var tidx = document.myForm.formAgent.selectedIndex\n"+
          "  var encAgent = document.myForm.formAgent.options[tidx].value\n"+
          "  var type = document.myForm.formType.selectedIndex\n"+
          "  var uid = trim(document.myForm."+
          ITEM_UID+
          ".value)\n"+
          "  if (uid.length > 0) {\n"+
          "    document.myForm.target=\"itemFrame\"\n"+
          "    if (type == 0) {\n"+
          "      document.myForm."+
          MODE+
          ".value= \""+
          MODE_TASK_DETAILS+
          "\"\n"+
          "    } else if (type == 1) {\n"+
          "      document.myForm."+
          MODE+
        ".value= \""+
        MODE_PLAN_ELEMENT_DETAILS+
        "\"\n"+
        "    } else if (type == 2) {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_ASSET_DETAILS+
        "\"\n"+
        "    } else if (type == 4) {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_ALL_MSG_MODS+
        "\"\n"+
        "    } else {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_XML_HTML_DETAILS+
        "\"\n"+
        "    }\n"+
        "    if (uid.charAt(0) == '/') {\n"+
        "      document.myForm."+
        ITEM_UID+
        ".value = encAgent + uid\n"+
        "    }\n"+
        "  } else {\n"+
        "    document.myForm.target=\"tablesFrame\"\n"+
        "    if (type == 0) {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_TASKS_SUMMARY+
        "\"\n"+
        "    } else if (type == 1) {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_ALL_PLAN_ELEMENTS+
        "\"\n"+
        "    } else if (type == 2) {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_ALL_ASSETS+
        "\"\n"+
        "    } else if (type == 4) {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_ALL_MSG_MODS+
        "\"\n"+
        "    } else {\n"+
        "      document.myForm."+
        MODE+
        ".value= \""+
        MODE_ALL_UNIQUE_OBJECTS+
        "\"\n"+
        "    }\n"+
        "  }\n"+
        "  document.myForm.action=\"/$\"+encAgent+\"");
      out.print(support.getPath());
      out.print("\"\n"+
          "  return true\n"+
          "}\n"+
          "\n"+
          "// javascript lacks String.trim()?\n"+
          "function trim(val) {\n"+
          "  var len = val.length\n"+
          "  if (len == 0) {\n"+
          "    return \"\"\n"+
          "  }\n"+
          "  var i\n"+
          "  for (i = 0; ((i < len) && (val.charAt(i) == ' ')); i++) {}\n"+
          "  if (i == len) {\n"+
          "    return \"\";\n"+
          "  }\n"+
          "  var j \n"+
          "  for (j = len-1; ((j > i) && (val.charAt(j) == ' ')); j--) {}\n"+
          "  j++\n"+
          "  if ((i == 0) && (j == len)) {\n"+
          "    return val\n"+
          "  }\n"+
          "  var ret = val.substring(i, j)\n"+
        "  return ret\n"+
        "}\n"+
        "// -->\n"+
        "</script>\n"+
        "<head>\n"+
        "<title>Logplan Search</title>\n"+
        "</head>\n"+
        "<body bgcolor=\"#F0F0F0\">\n"+
        "<noscript>\n"+
        "<b>This page needs Javascript!</b><br>\n"+
        "Consult your browser's help pages..\n"+
        "<p><p><p>\n"+
        "</noscript>\n"+
        "<form name=\"myForm\" method=\"get\" onSubmit=\"return mySubmit()\">\n"+
        "<input type=\"hidden\" name=\""+
        MODE+
        "\" value=\"fromJavaScript\">\n"+
        "<input type=\"hidden\" name=\""+
        LIMIT+
        "\" value=\"true\">\n"+
        "<select name=\"formAgent\">\n");
      // lookup all known cluster names
      //List names = support.getAllEncodedAgentNames();
      ServiceBroker sb = support.getServiceBroker();
      WhitePagesService wps = (WhitePagesService)
        sb.getService(this, WhitePagesService.class, null);
      Set set = null;
      try {
        set = wps.list("");
      }
      catch(Exception e) {
        e.printStackTrace(); 
      }
      if(set != null) { 
        TreeSet ts = new TreeSet(set);
        Iterator entries = ts.iterator();
        while(entries.hasNext()) {
          String n = (String)entries.next();
          String encodedName = support.encodeAgentName(n);
          out.print("  <option ");
          if (encodedName.equals(support.getEncodedAgentName())) {
            out.print("selected ");
          }
          out.print("value=\"");
          out.print(n);
          out.print("\">");
          out.print(n);
          out.print("</option>\n");
        }
      }
      sb.releaseService(this, WhitePagesService.class, wps);
      out.print(
          "</select><br>\n"+
          "<select name=\"formType\">\n"+
          "  <option selected value=\"0\">Tasks</option>\n"+
          "  <option value=\"1\">PlanElements</option>\n"+
          "  <option value=\"2\">Assets</option>\n"+
          "  <option value=\"3\">UniqueObjects</option>\n"+
          "  <option value=\"4\">Message Modifications</option>\n"+
          "</select><br>\n"+
          "UID:<input type=\"text\" name=\""+
          // user should enter an encoded UID
          ITEM_UID+
          "\" size=12><br>\n"+
	  "Sort results by UID<input type=\"checkbox\" name=\"sortByUID\" value=\"true\"><br>\n"+
          "<input type=\"submit\" name=\"formSubmit\" value=\"Search\"><br>\n"+
          "<p>\n"+
          // link to advanced search
          "<a href=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print(
          "?"+
          MODE+
          "="+
          MODE_ADVANCED_SEARCH_FORM+
          "\" target=\"advSearch\">Advanced search</a>"+
          "</form>\n"+
          "</body>\n"+
          "</html>\n");
    }

    /**
     * displayUniqueObjectDetails.
     */
    private void displayUniqueObjectDetails()
    {
      boolean asHTML;
      boolean isAttached;
      switch (mode) {
        default:
          // error, but treat as "MODE_XML_HTML_DETAILS"
        case MODE_XML_HTML_DETAILS:
          asHTML = true;
          isAttached = false;
          break;
        case MODE_XML_HTML_ATTACHED_DETAILS:
          asHTML = true;
          isAttached = true;
          break;
        case MODE_XML_RAW_DETAILS:
          asHTML = false;
          isAttached = false;
          break;
        case MODE_XML_RAW_ATTACHED_DETAILS:
          asHTML = false;
          isAttached = true;
          break;
      }
      if (DEBUG) {
        System.out.println(
            "\nDisplay UniqueObject "+
            (asHTML ? "HTML" : "Raw")+                     
            (isAttached ? " Attached" : "")+
            " Details");
      }
      // find base object using the specified UID
      UniqueObject baseObj = 
        findUniqueObjectWithUID(itemUID);
      // get the attached object
      Object attachedObj;
      if (isAttached) {
        // examine baseObj to find attached XMLizable
        // 
        // currently only a few cases are supported:
        //   Asset itself
        //   Task's "getDirectObject()"
        //   AssetTransfer's "getAsset()"
        if (baseObj instanceof Asset) {
          // same as above "MODE_XML_[HTML|RAW]_DETAILS"
          attachedObj = baseObj;
        } else if (baseObj instanceof Task) {
          attachedObj = ((Task)baseObj).getDirectObject();
        } else if (baseObj instanceof AssetTransfer) {
          attachedObj = ((AssetTransfer)baseObj).getAsset();
        } else {
          // error
          attachedObj = null;
        }
      } else {
        // the base itself
        attachedObj = baseObj;
      }
      Object xo = attachedObj;
      if (asHTML) {
        // print as HTML
        out.print("<html>\n<head>\n<title>");
        out.print(itemUID);
        out.print(
            " View</title>"+
            "</head>\n<body bgcolor=\"#F0F0F0\">\n<b>");
        // link to cluster
        printLinkToTasksSummary();
        out.print(
            "</b><br>\n"+
            "UniqueObject<br>");
        if (xo != null) {
          // link to non-html view of object
          out.print("<p>");
          printLinkToXML(xo, false);
          out.print("<br><hr><br><pre>\n");
          // print HTML-wrapped XML
          printXMLizableDetails(xo, true);
          out.print("\n</pre><br><hr><br>\n");
        } else {
          out.print("<p><font size=small color=mediumblue>");
          if (itemUID == null) {
            out.print("No UniqueObject selected.");
          } else if (baseObj == null) {
            out.print("No UniqueObject matching \"");
            out.print(itemUID);
            out.print("\" found.");
          } else if (attachedObj == null) {
            out.print("UniqueObject with UID \"");
            out.print(itemUID);
            out.print("\" of type ");
            out.print(baseObj.getClass().getName());
            out.print(" has null attached Object.");
          } else {
            out.print("UniqueObject with UID \"");
            out.print(itemUID);
            out.print("\" of type ");
            out.print(baseObj.getClass().getName());
            out.print(" has non-XMLizable attached Object: ");
            out.print(attachedObj.getClass().getName());
          }
          out.print("</font><p>\n");
        }
        out.print("</body></html>\n");
      } else {
        // print raw XML
        printXMLizableDetails(xo, false);
      }
      out.flush();
    }

    private static Field[] getModFields(Class clazz) {
      ArrayList list = new ArrayList();
      Field fields[] = clazz.getDeclaredFields();
      for (int i = 0; i < fields.length; i++) {
        if ((fields[i].getModifiers() & 
             (Modifier.FINAL | Modifier.PRIVATE | Modifier.PROTECTED)) == 0) {
          // good field
          Class type = fields[i].getType();
          if (type.isPrimitive() || type == String.class) {
            list.add(fields[i]);             
          } // end of if (type.isPrimitive() || type == String.class)
        } 
      } // end of for (int i = 0; i < fields.length; i++)
      return (Field[]) list.toArray(new Field[list.size()]);
    }

    private static boolean isTypeOK(Class clazz) {
      return clazz.isPrimitive() || 
        clazz == String.class ||
        clazz == Long.class ||
        clazz == Integer.class ||
        clazz == Short.class ||
        clazz == Byte.class ||
        clazz == Boolean.class ||
        clazz == Double.class ||
        clazz == Float.class ||
        clazz == Character.class;
    }

    private static Method[] getGetMethods(Class clazz) {
      ArrayList list = new ArrayList();
      HashMap setMethods = new HashMap();
      HashMap getMethods = new HashMap();

      Method methods[] = clazz.getDeclaredMethods();

      for (int i = 0; i < methods.length; i++) {
        if ((methods[i].getModifiers() & (Modifier.STATIC | Modifier.PRIVATE | Modifier.PROTECTED)) == 0) {
          String meth = methods[i].getName();
          if (meth.length() > 3) {
            Class retType = methods[i].getReturnType();
            Class[] paramTypes = methods[i].getParameterTypes();
            if (meth.startsWith("get") &&
                Character.isUpperCase(meth.charAt(3))) {
              if (isTypeOK(retType) && 
                  (paramTypes == null ||
                   paramTypes.length == 0)) {
                getMethods.put(methods[i].getName().substring(3), methods[i]);
              } // end of if (retType.isPrimitive() || retType == String.class)
            } else if (meth.startsWith("set") &&
                       Character.isUpperCase(meth.charAt(3))) {
              if (paramTypes.length == 1) {
                setMethods.put(methods[i].getName().substring(3), methods[i]);
              } // end of if (paramTypes.length == 1)
            }
          } // end of if (meth.length() > 3)
        } 
      }

      // now only use the intersection of keys:
      getMethods.keySet().retainAll(setMethods.keySet());
      
      // now go through all keys and find which get and set fields
      // match (and we can use)
      Iterator iter = getMethods.keySet().iterator();
      while (iter.hasNext()) {
        String key = (String) iter.next();
        Method get = (Method) getMethods.get(key);
        Method set = (Method) setMethods.get(key);
        if (get.getReturnType() == set.getParameterTypes()[0]) {
          list.add(get);
        } // end of if (get.getReturnType() == set.getParameterTypes[0])
      } // end of while (iter.hasNext())
      
      return (Method[]) list.toArray(new Method[list.size()]);
    }

    /**
     * Give a mechanism for editing an object through the java bean
     * mechanism.
     */
    private void displayEditFields() throws IOException, 
      IllegalAccessException, NoSuchFieldException, InvocationTargetException,
      NoSuchMethodException
    {
      if (DEBUG) {
        System.out.println("\nEdit fields of UniqueObject");
      }

      // find base object using the specified UID
      UniqueObject baseObj = 
        findUniqueObjectWithUID(itemUID);

      // do introspection to get the public fields and set/get methods
      
      Class clazz = baseObj.getClass();
      Field[] fields = getModFields(clazz);
      Method[] methods = getGetMethods(clazz);

      out.print("<html>\n<head>\n<title>");
      out.print(itemUID);
      out.print(" Edit</title>"+
                "</head>\n<body bgcolor=\"#F0F0F0\">\n<b>");
      out.print("Editable fields for Object ");
      out.print(itemUID);
      out.print("</b>\n<form name=\"edit\" method=\"POST\" action=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print("\">\n<input type=\"hidden\" name=\"");
      out.print(MODE);
      out.print("\" value=\"");
      out.print(MODE_EXEC_EDITS);
      out.print("\">\n<input type=\"hidden\" name=\"");
      out.print(ITEM_UID);
      out.print("\" value=\"");
      out.print(itemUID);
      out.print("\">\n" +
                "\n<table>\n");

      for (int i = 0; i < fields.length; i++) {
        out.print("<tr>\n<td>");
        out.print(fields[i].getName());
        out.print("</td>\n<td><input type=\"text\" name=\"field-");
        out.print(fields[i].getName());
        out.print("\" size=\"100\" value=\"");
        out.print(fields[i].get(baseObj));
        out.print("\"></td>\n</tr>\n");
      } // end of for (int i = 0; i < fields.length; i++)

      for (int i = 0; i < methods.length; i++) {
        out.print("<tr>\n<td>");
        String meth = methods[i].getName().substring(3);
        out.print(meth);
        out.print("</td>\n<td><input type=\"text\" name=\"method-");
        out.print(meth);
        out.print("\" size=\"100\" value=\"");
        out.print(methods[i].invoke(baseObj, null));
        out.print("</td>\n</tr>\n");
      } // end of for (int i = 0; i < methods.length; i++)

      out.print("</table>\n");
      out.print("<input type=\"submit\" name=\"submit\" value=\"Submit\">\n");
      out.print("</form>\n");
      out.print("</body></html>\n");
      out.flush();
    }

    private static Object convertVal(Class type, String fieldVal) {
      Object conv = null;
      if ("null".equals(fieldVal)) {
        return null;
      } // end of if ("null".equals(fieldVal))
      if (type == Integer.TYPE || type == Integer.class) {
        conv = Integer.valueOf(fieldVal);
      } else if (type == Long.TYPE || type == Long.class) {
        conv = Long.valueOf(fieldVal);
      } else if (type == Double.TYPE || type == Double.class) {
        conv = Double.valueOf(fieldVal);
      } else if (type == Float.TYPE || type == Float.class) {
        conv = Float.valueOf(fieldVal);
      } else if (type ==Character.TYPE || type == Character.class) {
        if (fieldVal.length() > 0) {
          conv = new Character(fieldVal.charAt(0));
        } else {
          throw new RuntimeException("Can't set character to " + fieldVal);
        } // end of else
      } else if (type == Byte.TYPE || type == Byte.class) {
        conv = Byte.valueOf(fieldVal);
      } else if (type == Short.TYPE || type == Short.class) {
        conv = Short.valueOf(fieldVal);
      } else if (type == Boolean.TYPE || type == Boolean.class) {
        conv = Boolean.valueOf(fieldVal);
      } else if (type == String.class) {
        conv = fieldVal;
      } 

      if (conv == null) {
        throw new RuntimeException("Couldn't set field type: " + type +
                                   " because I can't handle the type.");
        
      } // end of if (conv == null)
      return conv;
    }

    private void editFields() throws IOException, 
      IllegalAccessException, NoSuchFieldException, InvocationTargetException,
      NoSuchMethodException {
      if (DEBUG) {
        System.out.println("\nEdit fields of UniqueObject");
      }

      // find base object using the specified UID
      UniqueObject baseObj = 
        findUniqueObjectWithUID(itemUID);

      // do introspection to get the public fields and set/get methods
      
      Class clazz = baseObj.getClass();

      Iterator iter = fields.keySet().iterator();
      while (iter.hasNext()) {
        String fieldName = (String) iter.next();
        if (fieldName != null) {
          String fieldValue = (String) fields.get(fieldName);
          Field field = clazz.getDeclaredField(fieldName);
          // first see if the value has changed
          Object val = field.get(baseObj);
          if ((val == null && !"null".equals(fieldValue)) || 
              (val != null && !fieldValue.equals(val.toString()))) {
            // changed value
            Class type = field.getType();
            Object conv = convertVal(type, fieldValue);
            field.set(baseObj, conv);
          }
        } // end of if (fieldName != null)
      } // end of while (iter.hasNext())
      
      iter = methods.keySet().iterator();
      while (iter.hasNext()) {
        String methodName = (String) iter.next();
        if (methodName != null) {
          String methodValue = (String) methods.get(methodName);
          Method getMethod = clazz.getDeclaredMethod("get" + methodName, null);
          Class retType = getMethod.getReturnType();
          Method setMethod = clazz.getDeclaredMethod("set" + methodName,
                                                     new Class[] { retType });
          // first see if the value has changed
          Object val = getMethod.invoke(baseObj, null);
          if ((val == null && !"null".equals(methodValue)) || 
              (val != null && !methodValue.equals(val.toString()))) {
            // changed value
            Class type = setMethod.getParameterTypes()[0];
            Object conv = convertVal(type, methodValue);
            setMethod.invoke(baseObj, new Object[]{conv});
          }
        } // end of if (methodName != null)
      } // end of while (iter.hasNext())

      response.sendRedirect("/$" + support.getEncodedAgentName() +
                            support.getPath() +
                            "?" + ITEM_UID + "=" + itemUID +
                            "&" + MODE + "=" + MODE_XML_HTML_DETAILS);
    }

    /**
     * Display a page to save or load an object
     */
    private void displayLoadSavePage() throws IOException {
      String loadSave = "Load";
      if (itemUID != null) {
        loadSave = "Save";
      } 
      out.print("<html>\n<head>\n<title>");
      out.print(support.getEncodedAgentName());
      out.print(" ");
      out.print(loadSave);
      out.print(" Object</title>\n</head>\n"+
                "<body bgcolor=\"#F0F0F0\">\n");
      out.print("Enter the name of the file on the server:\n" +
                "<form method=\"POST\" action=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print("\">\n<input type=\"hidden\" name=\"");
      out.print(MODE);
      out.print("\" value=\"");
      out.print(mode);
      out.print("\">\n");
      if (itemUID != null) {
        out.print("<input type=\"hidden\" name=\"");
        out.print(ITEM_UID);
        out.print("\" value=\"");
        out.print(itemUID);
        out.print("\">\n");
      } // end of if (itemUID != null)
      out.print("<input type=\"text\" name=\"file\" " +
                "value=\"\" size=\"100\">\n" +
                "<input type=\"submit\" value=\"");
      out.print(loadSave);
      out.print("\" name=\"submit\">\n" +
                "</form>\n");
      out.print("</body>\n</html>\n");
    }

    private void loadSaveObject() throws IOException, ClassNotFoundException {
      if (file == null) {
        displayLoadSavePage();
        return;
      } // end of if (file == null)
      
      if (itemUID == null) {
        loadFile();
        return;
      } // end of if (itemUID == null)

      saveFile();
      return;
    }

    private void loadFile() throws IOException, ClassNotFoundException {
      FileInputStream fis = new FileInputStream(file);
      ObjectInputStream ois = new ObjectInputStream(fis);
      Object obj = ois.readObject();
      ois.close();
      fis.close();
      ServiceBroker sb = support.getServiceBroker();
      BlackboardService bbs = 
        (BlackboardService) sb.getService(this, BlackboardService.class, null);

      bbs.openTransaction();
      if (obj instanceof UniqueObject) {
        UniqueObject newObj = (UniqueObject) obj;
        itemUID = newObj.getUID().toString();
        UniqueObject oldObj = findUniqueObjectWithUID(itemUID);
        if (oldObj != null) {
          // remove the old one
          bbs.publishRemove(oldObj);
        } // end of if (oldObj != null)
      } // end of if (obj instanceof UniqueObject)
      bbs.publishAdd(obj);
      bbs.closeTransaction();

      response.sendRedirect("/$" + support.getEncodedAgentName() +
                            support.getPath() +
                            "?" + ITEM_UID + "=" + itemUID +
                            "&" + MODE + "=" + MODE_XML_HTML_DETAILS);
    }

    private void saveFile() throws IOException {
      FileOutputStream fos = new FileOutputStream(file);
      ObjectOutputStream oos = new ObjectOutputStream(fos);
      
      UniqueObject obj = findUniqueObjectWithUID(itemUID);
      oos.writeObject(obj);
      oos.close();
      fos.close();

      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " Save to "+
          file +
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "File " +
          file +
          " Saved successfully.\n" +
          "</body></html>\n");
    }

    /**
     * writes out the form using the given prefix for import and code
     * field names.
     */
    /**
     * display the form to enter code to run on an object.
     */
    private void displayCodeForm() throws IOException {
      out.print("<html><head><title>Enter code for ");
      out.print(itemUID);
      out.print("</title></head>\n<body>\n" +
                "The method body takes the object selected as an argument. " +
                "You may do with it as you please.<br>\n" +
                "<form name=\"edit\" method=\"POST\" action=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print("\">\n<input type=\"hidden\" name=\"");
      out.print(MODE);
      out.print("\" value=\"");
      out.print(MODE_EXECUTE_CODE);
      out.print("\">\n<input type=\"hidden\" name=\"");
      out.print(ITEM_UID);
      out.print("\" value=\"");
      out.print(itemUID);
      out.print("\">\n" +
                "<pre>");
      out.print(CODE_PACKAGE);
      out.print("</pre><textarea name=\"");
      out.print(IMPORTS);
      out.print("\" rows=5 cols=70>\n"+
                "import java.util.*;\n" +
                "import org.cougaar.core.util.*;\n" +
                "import org.cougaar.core.service.*;\n" +
                "</textarea><br>\n"+
                "<pre>");
      out.print(CODE_CLASS_TOP);
      out.print(CODE_METHOD_SIG);
      out.print("</pre>" + 
                "<textarea name=\"");
      out.print(CODE);
      out.print("\" rows=25 cols=70>\n"+
                "</textarea><br>\n<pre>");
      out.print(CODE_CLASS_BOTTOM);
      out.print("</pre><input type=\"checkbox\" name=\"" + PUBLISH_CHANGE +
                "\" value=\"true\"> PublishChange when finished.<br>\n" +
                "<input type=\"submit\" value=\"Execute\">\n" +
                "</form>\n" +
                "</body>\n" +
                "</html>\n");
    }

    private static String createClassPath() throws IOException {
      File libDir = new File(System.getProperty("org.cougaar.install.path"),"lib");
      File sysDir = new File(System.getProperty("org.cougaar.install.path"),"sys");
      FilenameFilter filter = new FilenameFilter() {
          public boolean accept(File dir, String name) {
            return name.endsWith(".jar") || name.endsWith(".zip");
          }
        };
      File libJars[] = libDir.listFiles(filter);
      File sysJars[] = sysDir.listFiles(filter);
      File jars[] = new File[libJars.length + sysJars.length];
      System.arraycopy(libJars, 0, jars, 0, libJars.length);
      System.arraycopy(sysJars, 0, jars, libJars.length, sysJars.length);
      StringBuffer cpBuf = new StringBuffer();
      for (int i = 0; i < jars.length; i++) {
        if (i != 0) {
          cpBuf.append(':');
        } // end of if (i != 0)
        cpBuf.append(jars[i].getCanonicalPath());
      } // end of for (int i = 0; i < jars.length; i++)
      return cpBuf.toString();
    }

    private static File getLatestJava() {
      File javaPath = new File("/usr/java");
      File javas[] = javaPath.listFiles(new FilenameFilter() {
          public boolean accept(File dir, String name) {
            return name.startsWith("j2sdk") || name.startsWith("jdk");
          }
        });
      String javaVersion = "0";
      for (int i = 0; i < javas.length; i++) {
        if (javas[i].isDirectory()) {
          String version;
          String name = javas[i].getName();
          if (name.startsWith("jdk")) {
            version = name.substring(3);
          } else {
            version = name.substring(5);
          } 
          if (version.compareTo(javaVersion) > 0) {
            javaVersion = version;
            javaPath = javas[i];
          } // end of if (version.compareTo(javaVersion) > 0)
        } // end of if (javas[i].isDirectory())
      } // end of for (int i = 0; i < javas.length; i++)
      return javaPath;
    }

    private static File getTmpDir() {
      File workspace = new File(System.getProperty("org.cougaar.workspace"));
      File tmpDir;
      int dirNum = 1;
      do {
        tmpDir = new File(workspace, "editobj" + dirNum);
        dirNum++;
      } while (tmpDir.exists() && tmpDir.isFile());
      if (!tmpDir.exists()) {
        tmpDir.mkdir();
      } // end of if (!tmpDir.exists())
      return tmpDir;
    }

    private String getCode(String top, String sig) {
      StringBuffer completeCode = new StringBuffer();
      completeCode.append(CODE_PACKAGE);
      completeCode.append(imports);
      completeCode.append("\n");
      completeCode.append(top);
      if (middle != null) {
        completeCode.append(middle);
      } // end of if (middle != null)
      completeCode.append(sig);
      completeCode.append(code);
      completeCode.append("\n");
      completeCode.append(CODE_CLASS_BOTTOM);
      String javaCode = completeCode.toString();
      return javaCode;
    }

    private static class CompileAction implements PrivilegedAction {
      JavaCompiler _jc;
      File         _javaFile;
      File         _classFile;

      private static class TempClassLoader extends ClassLoader {
        Class _clazz;
        public TempClassLoader(ClassLoader parent, File classFile) 
          throws FileNotFoundException, IOException, ClassNotFoundException {
          super(parent);
          FileInputStream fis = new FileInputStream(classFile);
          ByteArrayOutputStream bout = new ByteArrayOutputStream();
          byte buf[] = new byte[1000];
          int len;
          while ((len = fis.read(buf)) > 0) {
            bout.write(buf, 0, len);
          } // end of while ((len = fis.read(buf)) > 0)
          _clazz = defineClass("tmp.TmpEditObject", bout.toByteArray(), 
                               0, bout.size());
        }

        public Class findClass(String name) throws ClassNotFoundException {
          if (name.equals("tmp.TmpEditObject")) {
            return _clazz;
          } else {
            return super.findClass(name);
          } 
        }
      }

      public CompileAction(JavaCompiler jc, File javaFile, File classFile) {
        _jc = jc;
        _javaFile = javaFile;
        _classFile = classFile;
      }

      public Object run() //throws FileNotFoundException, IOException, ClassNotFoundException 
      {
        try {
          boolean worked = _jc.compile(_javaFile.getCanonicalPath());
          if (worked == false) {
            return null;
          } // end of if (worked == false)
      
          ClassLoader classLoader = 
            new TempClassLoader(this.getClass().getClassLoader(), 
                                _classFile);
          return classLoader.loadClass("tmp.TmpEditObject");
        } catch (Exception e) {
          return e;
        }
      }
    }

    /**
     * Compiles and executes the given code
     */
    private void runCode() throws IOException, UnsupportedEncodingException,
      ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
      InvocationTargetException {
      out.print("<html><head><title>Enter code for ");
      out.print(itemUID);
      out.print("</title></head>\n<body>\n" +
                "<pre>Creating compiler...\n");
      JavaCompiler jc = new SunJavaCompiler();
      jc.setEncoding("UTF-8");
      out.println("Finding jar files in lib and sys...");
      String classpath = createClassPath();
      out.println("Setting class path to " + classpath);
      jc.setClasspath(classpath);
      out.println("Discovering latest version of java...");
      File javaPath = 
        (File) AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
              return getLatestJava();
            }
          });
      File javacPath = new File(javaPath,"bin");
      javacPath = new File(javacPath,"javac");
      out.println("Setting java compiler path to " + 
                  javacPath.getCanonicalPath() + " ...");
//       jc.setCompilerPath(javacPath.getCanonicalPath());
      out.println("Setting the output stream to the Servlet ...");
      ByteArrayOutputStream tmpOut = new ByteArrayOutputStream();
      jc.setMsgOutput(tmpOut);
      out.println("Getting the workspace directory ...");
      File tmpDir = getTmpDir();
      out.println("Setting the temporary directory to " + 
                  tmpDir.getCanonicalPath() + " ...");
      jc.setOutputDir(tmpDir.getCanonicalPath());
      out.println("Compiling code: ");
      final String javaCode = getCode(CODE_CLASS_TOP,CODE_METHOD_SIG);
      out.println(javaCode);

      File javaFile = new File(tmpDir,"TmpEditObject.java");
      FileWriter fw = new FileWriter(javaFile);
      fw.write(javaCode);
      fw.close();

      tmpDir = new File(tmpDir,"tmp"); 
      File classFile = new File(tmpDir,"TmpEditObject.class");
      Object obj = AccessController.doPrivileged(new CompileAction(jc, 
                                                                   javaFile,
                                                                   classFile));

      if (obj instanceof Exception) {
        ((Exception) obj).printStackTrace(out);
      } else {
        Class c = (Class) obj;
        out.print("\n<b>");
        out.print(tmpOut.toString("UTF-8"));
        out.println("</b>");
        tmpOut.reset();
        if (c == null) {
          out.println("Compile failed");
        } else {
          // compile succeeded. run it
          out.println("Executing ...");
          Method execMethod = 
            c.getDeclaredMethod("execute", new Class[] { Object.class });
          Object target = findUniqueObjectWithUID(itemUID);
          execMethod.invoke(null, new Object[] { target });
          if (publishChange) {
            out.println("Doing BlackboardService PublishChange on the object...");
            ServiceBroker sb = support.getServiceBroker();
            BlackboardService bbs = 
              (BlackboardService) sb.getService(this, BlackboardService.class,
                                                null);
            bbs.openTransaction();
            bbs.publishChange(target);
            bbs.closeTransaction();
          } // end of if (publishChange)
          out.println("Succeeded!");
        } 
      } // end of else
      out.println("</pre></body></html>");
    }

    /**
     * displayAllUniqueObjects.
     */
    private void displayAllUniqueObjects()
    {
      if (DEBUG) {
        System.out.println("\nDisplay All UniqueObjects");
      }
      Collection col = findAllUniqueObjects();
      int numUniqueObjects = col.size();
      Iterator uoIter = col.iterator();
      if (DEBUG) {
        System.out.println("Fetched UniqueObjects");
      }
      // begin page
      out.print(
          "<html>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " UniqueObjects"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\">\n"+
          "<center>");
      if (limit && (numUniqueObjects > DEFAULT_LIMIT)) {
        out.print("Showing first <b>");
        out.print(DEFAULT_LIMIT);
        out.print("</b> of ");
      }
      out.print("<b>");
      out.print(numUniqueObjects);
      out.print(
          "</b> UniqueObject");
      if (numUniqueObjects != 1) {
        out.print("s");
      }
      out.print(" at ");
      out.print(support.getEncodedAgentName());
      out.print("</center>\n");
      if (limit && (numUniqueObjects > DEFAULT_LIMIT)) {
        out.print("<center>");
        // link to all uniqueObjects.
        printLinkToAllUniqueObjects(
            0, numUniqueObjects, false);
        out.print("</center>\n");
      }
      out.print(
          "\n<table align=center border=1 cellpadding=1\n"+
          " cellspacing=1 width=75%\n"+
          " bordercolordark=#660000 bordercolorlight=#cc9966>\n"+
          "<tr>\n"+
          "<td colspan=2>"+
          "<font size=+1 color=mediumblue><b>UniqueObjects</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td><font color=mediumblue><b>UID</font></b></td>\n"+
          "<td><font color=mediumblue><b>Type</font></b></td>\n"+
          "</tr>\n");
      if (numUniqueObjects > 0) {
        // print table rows
        int rows = 0;
        while (uoIter.hasNext()) {
          UniqueObject uo = (UniqueObject)uoIter.next();
          int itemType = getItemType(uo);
          out.print(
              "<tr>\n"+
              "<td>");
          switch (itemType) {
            case ITEM_TYPE_ALLOCATION:
            case ITEM_TYPE_EXPANSION:
            case ITEM_TYPE_AGGREGATION:
            case ITEM_TYPE_DISPOSITION:
            case ITEM_TYPE_ASSET_TRANSFER:
              printLinkToPlanElement((PlanElement)uo);
              break;
            case ITEM_TYPE_TASK:
              printLinkToLocalTask((Task)uo);
              break;
            case ITEM_TYPE_ASSET:
              // found this asset in local LogPlan
              printLinkToLocalAsset((Asset)uo);
              break;
            case ITEM_TYPE_WORKFLOW:
            default:
              printLinkToXML(uo, true);
              break;
          }
          out.print(
              "</td>\n"+
              "<td>");
          if (itemType != ITEM_TYPE_OTHER) {
            out.print(ITEM_TYPE_NAMES[itemType]);
          } else {
            out.print("<font color=red>");
            out.print(uo.getClass().getName());
            out.print("</font>");
          }
          out.print(
              "</td>\n"+
              "</tr>\n");
          if ((++rows % DEFAULT_LIMIT) == 0) {
            if (limit) {
              // limit to DEFAULT_LIMIT
              break;
            }
            // restart table
            out.print("</table>\n");
            out.flush();
            out.print("<table align=center border=1 cellpadding=1\n"+
                      " cellspacing=1 width=75%\n"+
                      " bordercolordark=#660000 bordercolorlight=#cc9966>\n");
          }
        }
        // end table
        out.print("</table>\n");
        if (limit && (rows == DEFAULT_LIMIT)) {
          // link to unlimited view
          out.print(
              "<p>"+
              "<center>");
          printLinkToAllUniqueObjects(
              0, numUniqueObjects, false);
          out.print(
              "<br>"+
              "</center>\n");
        }
      } else {
        out.print(
            "</table>"+
            "<center>"+
            "<font color=mediumblue>\n"+
            "No UniqueObjects found in ");
        out.print(support.getEncodedAgentName());
        out.print(
            "\n...try again"+
            "</font>"+
            "</center>\n");
      }
      out.print("<a href=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print("?" + MODE + "=" + MODE_LOAD_SAVE_OBJECT);
      out.print("\" target=\"load\">Load Object</a>\n");
      // end page
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    // keep a Map of ordered (name, value) pairs
    private static PropertyTree TEMPLATE_PREDS = null;
    private static synchronized final PropertyTree getTemplatePreds() { 
      if (TEMPLATE_PREDS == null) {
        String fname = System.getProperty(PREDS_FILENAME_PROPERTY);
        if (fname == null) {
          fname = DEFAULT_PREDS_FILENAME;
        }
        try {
          InputStream in = ConfigFinder.getInstance().open(fname);
          TEMPLATE_PREDS = PredTableParser.parse(in);
        } catch (IOException ioe) {
          System.err.println("Unable to open predicate file \""+fname+"\":");
          TEMPLATE_PREDS = new PropertyTree(1);
          TEMPLATE_PREDS.put("Unable to load \\\\"+fname+"\\\"", "");
        }
      }
      return TEMPLATE_PREDS;
    }

    private void displayAdvancedSearchForm()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Advanced Search Form");
      }
      out.print(
          "<html>\n"+
          "<script language=\"JavaScript\">\n"+
          "<!--\n"+
          "function mySubmit() {\n"+
          "  var tidx = document.myForm.formAgent.selectedIndex\n"+
          "  var encAgent = document.myForm.formAgent.options[tidx].value\n"+
          "  document.myForm.action=\"/$\"+encAgent+\"");
      out.print(support.getPath());
      out.print(
          "\"\n"+
          "  return true\n"+
          "}\n"+
          "\n"+
          "function setPred() {\n"+
          "  var i = document.myForm.formPred.selectedIndex\n"+
          "  var s\n"+
          "  switch(i) {\n"+
          "    default: alert(\"unknown (\"+i+\")\"); break\n");
      PropertyTree templatePreds = getTemplatePreds();
      int nTemplatePreds = templatePreds.size();
      for (int i = 0; i < nTemplatePreds; i++) {
        out.print("case ");
        out.print(i);
        out.print(": s=\"");
        out.print(templatePreds.getValue(i));
        out.print("\"; break\n");
      }
      out.print(
          "  }\n"+
          "  document.myForm."+
          PREDICATE_STYLE+
          ".selectedIndex=0\n"+
          "  document.myForm.pred.value=s\n"+
          "}\n"+
          "// -->\n"+
          "</script>\n"+
          "<head>\n"+
          "<title>");
      out.print(support.getEncodedAgentName());
      out.print(
          " Advanced Search Form"+
          "</title>\n"+
          "</head>\n"+
          "<body bgcolor=\"#F0F0F0\" "+
          " onload=\"setPred()\">\n"+
          "<font size=+1><b>Advanced Search</b></font><p>"+
          // should add link here for usage!!!
          "<noscript>\n"+
          "<b>This page needs Javascript!</b><br>\n"+
          "Consult your browser's help pages..\n"+
          "<p><p><p>\n"+
          "</noscript>\n"+
          "<form name=\"myForm\" method=\"get\" "+
          "target=\"predResults\" onSubmit=\"return mySubmit()\">\n"+
          "Search cluster <select name=\"formAgent\">\n");
      // lookup all known cluster names
      ServiceBroker sb = support.getServiceBroker();
      WhitePagesService wps = (WhitePagesService)
        sb.getService(this, WhitePagesService.class, null);
      Set set = null;
      try {
        set = wps.list("");
      }
      catch(Exception e) {
        e.printStackTrace(); 
      }
      if(set != null) {
        TreeSet ts = new TreeSet(set);
        Iterator entries = ts.iterator();
        while(entries.hasNext()) {
          String n = (String)entries.next();
          String encodedName = support.encodeAgentName(n);
          out.print("  <option ");
          if (encodedName.equals(support.getEncodedAgentName())) {
            out.print("selected ");
          }
          out.print("value=\"");
          out.print(n);
          out.print("\">");
          out.print(n);
          out.print("</option>\n");
        }
      }
      sb.releaseService(this, WhitePagesService.class, wps);
      out.print("</select><br>\n");
      if (nTemplatePreds > 0) {
        out.print(
            "<b>Find all </b>"+
            "<select name=\"formPred\" "+
            "onchange=\"setPred()\">\n");
        for (int i = 0; i < nTemplatePreds; i++) {
          out.print("<option>");
          out.print(templatePreds.getKey(i));
          out.print("</option>\n");
        }
        out.print(
            "</select><br>\n");
      }
      out.print(
          "<input type=\"checkbox\" name=\""+
          LIMIT+
          "\" value=\"true\" checked>"+
          "limit to "+
          DEFAULT_LIMIT+
          " matches<br>\n"+
          "<input type=\"submit\" name=\"formSubmit\" value=\"Search\"><br>\n"+
          "<p><hr>\n"+
          "Style: <select name=\""+
          PREDICATE_STYLE+
          "\">\n"+
          "<option selected>Lisp format</option>\n"+
          "<option>XML format</option>\n"+
          "</select>,&nbsp;\n"+
          "<input type=\"checkbox\" name=\""+
          PREDICATE_DEBUG+
          "\" value=\"true\">View parsed predicate<br>\n"+
          "<textarea name=\""+
          PREDICATE+
          "\" rows=15 cols=70>\n"+
          "</textarea><br>\n"+
        "<input type=\"hidden\" name=\""+
        MODE+
        "\" value=\""+
        MODE_ADVANCED_SEARCH_RESULTS+
        "\">\n"+
        "<br><hr>\n"+
        "</form>\n"+
        "<i><b>Documentation</b> is available in the \"contract\" "+
        "guide and javadocs, as "+
        "/src/org/cougaar/lib/contract/lang/index.html"+
        "</i>"+
        "</body>"+
        "</html>\n");
      out.flush();
    }

    private void displayAllMsgMods() {
      out.print("<html>\n<head>\n" +
                "<title>Message Modifications</title>\n" +
                "</head>\n<body>\n" +
                "<h1>Message Modifications</h1>\n" +
                "<table width=\"75%\">\n" +
                "<tr>\n" +
                "<td>Message Modification Name</td>\n" +
                "<td>Actions</td>\n" +
                "</tr>\n");
      Enumeration mods = MessageInterceptorAspect.getInterceptorNames();
      int count = 0;
      while (mods.hasMoreElements()) {
        String mod = (String) mods.nextElement();
        out.print("<tr><td>");
        out.print(mod);
        out.print("</td><td><a href=\"/$");
        out.print(support.getEncodedAgentName());
        out.print(support.getPath());     
        out.print("?"+MODE+"="+MODE_DEL_MSG_MOD+"&"+
                  MOD_NAME+"="+mod);
        out.print("\">Delete</a></td></tr>\n");
      } // end of while (mods.hasMoreElements())
      out.print("</table>\n" + 
                "<a href=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());     
      out.print("?"+MODE+"="+MODE_ENTER_MSG_MOD);
      out.print("\" target=\"msgmod\">Add Message Modification</a><br>\n" +
                "</body></html>");
    }

    private void delMsgMod() {
      out.print("<html>\n<head>\n" +
                "<title>Deleting Message Modification</title>\n" +
                "</head>\n<body>\n" +
                "<h1>Deleting Message Modification</h1>\n");
      MessageInterceptorAspect.deleteInterceptor(msgName);
      out.print("deleted " + msgName);
      out.print("</body></html>");
    }

    private void displayMsgModForm() {
      out.print("<html>\n<head>\n" +
                "<title>Enter Message Modification Code</title>\n" +
                "</head>\n<body>\n" +
                "The method takes the message that is being sent or " +
                "received as an argument. You may modify it as you please " +
                "and return <code>true</code> if the message should be " +
                "delivered or <code>false</code> if the message should be " +
                "dropped.<br>" + 
                "<form name=\"edit\" method=\"POST\" action=\"/$");
      out.print(support.getEncodedAgentName());
      out.print(support.getPath());
      out.print("\">\n<input type=\"hidden\" name=\"");
      out.print(MODE);
      out.print("\" value=\"");
      out.print(MODE_SAVE_MSG_MOD);
      out.print("\">\n" +
                "<textarea name=\"");
      out.print(IMPORTS);
      out.print("\" rows=5 cols=70>\n"+
                "import java.util.*;\n" +
                "import org.cougaar.core.util.*;\n" +
                "import org.cougaar.core.service.*;\n" +
                "import org.cougaar.core.mts.*;\n" +
                "import org.cougaar.core.agent.*;\n" +
                "</textarea><br>\n"+
                "<pre>");
      out.print(CODE_MSG_TOP);
      out.print("</pre>" + 
                "<textarea name=\"");
      out.print(MIDDLE);
      out.print("\" rows=5 cols=70>\n"+
                "</textarea><br>\n<pre>");
      out.print(CODE_MSG_SIG);
      out.print("</pre>" + 
                "<textarea name=\"");
      out.print(CODE);
      out.print("\" rows=25 cols=70>\n"+
                "</textarea><br>\n<pre>");
      out.print(CODE_CLASS_BOTTOM);
      out.print("</pre>\n" +
                "Name this: <input type=\"text\" size=\"40\" name=\"");
      out.print(MOD_NAME);
      out.print("\">\n" +
                "<input type=\"submit\" value=\"Save\">\n" +
                "</form>\n" +
                "</body>\n" +
                "</html>\n");
    }

    private JavaCompiler createJavaCompiler(OutputStream out) 
      throws IOException {
      JavaCompiler jc = new SunJavaCompiler();
      jc.setEncoding("UTF-8");
      String classpath = createClassPath();
      jc.setClasspath(classpath);
      File javaPath = 
        (File) AccessController.doPrivileged(new PrivilegedAction() {
            public Object run() {
              return getLatestJava();
            }
          });
      File javacPath = new File(javaPath,"bin");
      javacPath = new File(javacPath,"javac");
      jc.setMsgOutput(out);
      File tmpDir = getTmpDir();
      jc.setOutputDir(tmpDir.getCanonicalPath());
      return jc;
    }

    private Object compile(JavaCompiler jc, String javaCode) 
      throws IOException, InstantiationException, IllegalAccessException {
      File tmpDir = getTmpDir();
      String className = "TmpEditObject";
      File javaFile = new File(tmpDir, className + ".java");
      FileWriter fw = new FileWriter(javaFile);
      fw.write(javaCode);
      fw.close();

      tmpDir = new File(tmpDir,"tmp"); 
      File classFile = new File(tmpDir, className + ".class");
      Object obj = AccessController.doPrivileged(new CompileAction(jc, 
                                                                   javaFile,
                                                                   classFile));
      if (obj instanceof Exception) {
        return obj;
      } 
      if (obj == null) {
        return null;
      } // end of if (obj == null)
      
      Class c = (Class) obj;
      return c.newInstance();
    }

    private void saveMsgMod() throws IOException, InstantiationException, 
      IllegalAccessException {
      ByteArrayOutputStream compileOut = new ByteArrayOutputStream();
      JavaCompiler jc = createJavaCompiler(compileOut);
      
      out.print("<html>\n" + 
                "<head>\n" +
                "<title>Saving Message Modifications</title>\n" +
                "</head>\n" +
                "<body>\n");
      String javaCode = getCode(CODE_MSG_TOP, CODE_MSG_SIG);
      out.println("<pre>Compiling code...");
      out.print(javaCode);

      Object obj = compile(jc, javaCode);
      out.print("\n<b>");
      out.print(compileOut.toString("UTF-8"));
      out.print("\n</b>");
      compileOut.reset();
      if (obj instanceof Exception) {
        out.println();
        ((Exception) obj).printStackTrace(out);
      } else if (obj != null) {
        out.println("Success!");
        SendQueueInterceptor sqi = (SendQueueInterceptor) obj;
        MessageInterceptorAspect.addInterceptor(msgName, sqi);
      }
      out.println("</pre>\n" + 
                  "</body>\n" +
                  "</html>\n");
    }

    private void displayAdvancedSearchResults()
    {
      if (DEBUG) {
        System.out.println("\nDisplay Advanced Search Results");
      }

      String inputPred = pred;

      out.print("<html><head><title>");
      out.print(support.getEncodedAgentName());
      out.print(
         " Advanced Search Results</title><head>\n"+
         "<body bgcolor=\"#F0F0F0\"><p>\n"+
         "Search <b>");
      out.print(support.getEncodedAgentName());
      out.print("</b> using Lisp-style predicate: <br><pre>\n");
      out.print(inputPred);
      out.print("</pre><p>\n<hr><br>\n");

      // parse the input to create a unary predicate
      UnaryPredicate parsedPred = null;
      try {
        parsedPred = UnaryPredicateParser.parse(inputPred);
      } catch (Exception parseE) {
        // display compile error
        out.print(
            "<font color=red size=+1>Parsing failure:</font>"+
            "<p><pre>");
        out.print(parseE.getMessage());
        out.print("</pre></body></html>");
        out.flush();
        return;
      }

      if (parsedPred == null) {
        // empty string?
        out.print(
            "<font color=red size=+1>Given empty string?</font>"+
            "</body></html>");
        out.flush();
        return;
      }

      if (predDebug) {
        // this is useful in general, but clutters the screen...
        out.print("Parsed as:<pre>\n");
        out.print(parsedPred);
        out.print("</pre><br><hr><br>\n");
      }

      Collection col = searchUsingPredicate(parsedPred);
      int numObjects = col.size();
      Iterator oIter = col.iterator();
      if (DEBUG) {
        System.out.println("Fetched Matching Objects["+numObjects+"]");
      }
      out.print(
          "<b>Note:</b> "+
          "links below will appear in the \"");
      out.print(support.getPath());
      out.print(
          "\" lower-left \"details\" "+
          "frame<p>"+
          "<center>");
      if (limit && (numObjects > DEFAULT_LIMIT)) {
        out.print("Showing first <b>");
        out.print(DEFAULT_LIMIT);
        out.print("</b> of ");
      }
      out.print("<b>");
      out.print(numObjects);
      out.print("</b> Object");
      if (numObjects != 1) {
        out.print("s");
      }
      out.print(" at ");
      out.print(support.getEncodedAgentName());
      out.print("</center>\n");
      out.print(
          "\n<table align=center border=1 cellpadding=1\n"+
          " cellspacing=1 width=75%\n"+
          " bordercolordark=#660000 bordercolorlight=#cc9966>\n"+
          "<tr>\n"+
          "<td colspan=2>"+
          "<font size=+1 color=mediumblue><b>Matching Objects</b></font>"+
          "</td>\n"+
          "</tr>\n"+
          "<tr>\n"+
          "<td><font color=mediumblue><b>UID</font></b></td>\n"+
          "<td><font color=mediumblue><b>Type</font></b></td>\n"+
          "</tr>\n");
      if (numObjects > 0) {
        // print table rows
        int rows = 0;
        while (oIter.hasNext()) {
          Object o = oIter.next();
          int itemType = getItemType(o);
          out.print(
              "<tr>\n"+
              "<td>");
          switch (itemType) {
            case ITEM_TYPE_ALLOCATION:
            case ITEM_TYPE_EXPANSION:
            case ITEM_TYPE_AGGREGATION:
            case ITEM_TYPE_DISPOSITION:
            case ITEM_TYPE_ASSET_TRANSFER:
              printLinkToPlanElement((PlanElement)o);
              break;
            case ITEM_TYPE_TASK:
              printLinkToLocalTask((Task)o);
              break;
            case ITEM_TYPE_ASSET:
              // found this asset in local LogPlan
              printLinkToLocalAsset((Asset)o);
              break;
            case ITEM_TYPE_WORKFLOW:
            default:
              printLinkToXML(o, true);
              break;
          }
          out.print(
              "</td>\n"+
              "<td>");
          if (itemType != ITEM_TYPE_OTHER) {
            out.print(ITEM_TYPE_NAMES[itemType]);
          } else {
            out.print("<font color=red>");
            out.print(o.getClass().getName());
            out.print("</font>");
          }
          out.print(
              "</td>\n"+
              "</tr>\n");
          if ((++rows % DEFAULT_LIMIT) == 0) {
            if (limit) {
              // limit to DEFAULT_LIMIT
              break;
            }
            // restart table
            out.print("</table>\n");
            out.flush();
            out.print(
                "<table align=center border=1 cellpadding=1\n"+
                " cellspacing=1 width=75%\n"+
                " bordercolordark=#660000 bordercolorlight=#cc9966>\n");
          }
        }
        // end table
        out.print("</table>\n");
      } else {
        out.print(
            "</table>"+
            "<center>"+
            "<font color=mediumblue>\n"+
            "No matching Objects found in ");
        out.print(support.getEncodedAgentName());
        out.print(
            "\n...try again"+
            "</font>"+
            "</center>\n");
      }
      // end page
      out.print(
          "</body>"+
          "</html>\n");
      out.flush();
    }

    /** END DISPLAY ROUTINES **/

    /** BEGIN PRINT ROUTINES **/

    /**
     * printTaskDetails.
     *
     * Includes support for printing early-best-latest dates
     * for END_TIMEs with VScoringFunctions.
     *
     */
    private void printTaskDetails(Task task)
    {
      out.print(
          "<ul>\n"+
          "<li>"+
          "<font size=small color=mediumblue>UID= ");
      // show uid
      UID tu;
      String tuid;
      if (((tu = task.getUID()) != null) &&
          ((tuid = tu.toString()) != null)) {
        out.print(tuid);
      } else {
        out.print("</font><font color=red>missing</font>");
      }
      out.print(
          "</font>"+
          "</li>\n"+
          "<li>"+
          "<font size=small color=mediumblue>Verb= ");
      // show verb
      Verb verb = task.getVerb();
      if (verb != null) {
        out.print(verb.toString());
      } else {
        out.print("</font><font color=red>missing");
      }
      out.print(
          "</font>"+
          "</li>\n"+
          "<li>"+
          "<font size=small color=mediumblue>"+
          "DirectObject= ");
      // link to Task's direct object
      printLinkToTaskDirectObject(task);
      out.print(
          "</font>"+
          "</li>\n"+
          "<li>"+
          "<font size=small color=mediumblue>"+
          "PlanElement= ");
      // link to plan element
      PlanElement pe = task.getPlanElement();
      printLinkToPlanElement(pe);
      out.print(
          " (");
      int peType = getItemType(pe);
      if (peType != ITEM_TYPE_OTHER) {
        out.print(ITEM_TYPE_NAMES[peType]);
      } else {
        out.print("<font color=red>");
        if (pe != null) {
          out.print(pe.getClass().getName());
        } else {
          out.print("null");
        }
        out.print("</font>");
      }
      out.print(
          ")"+
          "</font>"+
          "</li>");
      // show parent task(s) by UID
      if (task instanceof MPTask) {
        out.print(
            "<li>\n"+
            "<font size=small color=mediumblue>"+
            "ParentTasks<br>\n"+
            "<ol>\n");
        /********************************************************
         * Only want UIDs, so easy fix when getParentTasks is   *
         * replaced with getParentTaskUIDs.                     *
         ********************************************************/
        Enumeration parentsEn = ((MPTask)task).getParentTasks();
        while (parentsEn.hasMoreElements()) {
          Task pt = (Task)parentsEn.nextElement();
          out.print("<li>");
          // parents of an MPTask are always local
          printLinkToLocalTask(pt);
          out.print("</li>\n");
        }
        out.print(
            "</ol>\n"+
            "</font>\n"+
            "</li>\n");
      } else {
        out.print(
            "<li>\n"+
            "<font size=small color=mediumblue>"+
            "ParentTask= \n");
        printLinkToParentTask(task);
        out.print(
            "</font>"+
            "</li>\n");
      }
      // show preferences
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "Preferences"+
          "</font>"+
          "<ol>\n");
      Enumeration enpref = task.getPreferences();
      while (enpref.hasMoreElements()) {
        Preference pref = (Preference)enpref.nextElement();
        int type = pref.getAspectType();
        out.print(
            "<font size=small color=mediumblue>"+
            "<li>");
        out.print(AspectValue.aspectTypeToString(type));
        out.print("= ");
        ScoringFunction sf = pref.getScoringFunction();
        AspectScorePoint best = sf.getBest();
        double bestVal = best.getValue();
        String bestString;
        if ((type == AspectType.START_TIME) || 
            (type == AspectType.END_TIME)) {
          if ((type == AspectType.END_TIME) &&
              (sf instanceof ScoringFunction.VScoringFunction)) {
            bestString = 
              "<br>" + 
              "Earliest " + getTimeString(getEarlyDate (sf)) + 
              "<br>" + 
              "Best " + getTimeString((long)bestVal) +
              "<br>" + 
              "Latest " + getTimeString(getLateDate (sf));
          } else {
            bestString = getTimeString((long)bestVal);
          }
        } else {
          bestString = Double.toString(bestVal);
        }
        out.print(bestString);
        out.print(
            "</li>"+
            "</font>\n");
      }
      out.print(
          "</ol>"+
          "</li>\n"+
          "<li>\n"+
          "<font size=small color=mediumblue>"+
          "PrepositionalPhrases<br>\n"+
          "<ol>\n");
      // show prepositional phrases
      Enumeration enprep = task.getPrepositionalPhrases();
      while (enprep.hasMoreElements()) {
        PrepositionalPhrase pp = 
          (PrepositionalPhrase)enprep.nextElement();
        out.print("<li>");
        if (pp != null) {
          String prep = pp.getPreposition();
          out.print("<i>");
          out.print(prep);
          out.print(" </i>");
          Object indObj = pp.getIndirectObject();
          if (!(indObj instanceof Schedule)) {
            // typical case
            printObject(indObj);
          } else {
            // display full schedule information
            Schedule sc = (Schedule)indObj;
            out.print(
                "Schedule:<ul>\n"+
                "<li>Type: ");
            out.print(sc.getScheduleType());
            if (sc.isEmpty()) {
              out.print("</li>\n<li><font color=red>empty</font>");
            } else {
              out.print("</li>\n<li>StartTime= ");
              out.print(getTimeString(sc.getStartTime()));
              out.print("</li>\n<li>EndTime= ");
              out.print(getTimeString(sc.getEndTime()));
              out.print("</li>\n");
              out.print("<li>Elements:");
              out.print("\n<ol>\n");
              Iterator iterator = new ArrayList(sc).iterator();
              while (iterator.hasNext()) {
                ScheduleElement se = (ScheduleElement)iterator.next();
                out.print(
                    "<li>StartTime= ");
                out.print(getTimeString(se.getStartTime()));
                out.print("<br>EndTime= ");
                out.print(getTimeString(se.getEndTime()));
                if (se instanceof LocationRangeScheduleElement) {
                  LocationRangeScheduleElement locSE = 
                    (LocationRangeScheduleElement)se;
                  out.print("<br>StartLocation= ");
                  out.print(locSE.getStartLocation());
                  out.print("<br>EndLocation= ");
                  out.print(locSE.getEndLocation());
                  if (locSE instanceof ItineraryElement) {
                    out.print("<br>Verb= ");
                    out.print(((ItineraryElement)locSE).getRole());
                  }
                } else if (se instanceof LocationScheduleElement) {
                  out.print("<br>Location= ");
                  out.print(((LocationScheduleElement)se).getLocation());
                }
                out.print("</li>\n");
              } 
              out.print("</ol>\n");
            }
            out.print("</li>\n</ul>\n");
          }
        } else {
          out.print("<font color=red>null</font>");
        }
        out.print("</li>");
      }
      out.print(
          "</font>"+
          "</ol>\n"+
          "</li>\n");
      out.print("</ul>\n");
      // link to XML view
      out.print("<font size=small color=mediumblue>");
      // this task is local
      printLinkToXML(task, true);
      out.print("</font>");
    }

    /**
     * Part of support for printing early-best-latest dates
     * for END_TIMEs with VScoringFunctions.
     */
    private static long getEarlyDate(ScoringFunction vsf) {
      Enumeration validRanges = getValidEndDateRanges(vsf);
      while (validRanges.hasMoreElements()) {
        AspectScoreRange range = 
          (AspectScoreRange)validRanges.nextElement();
        return 
          ((AspectScorePoint)range.getRangeStartPoint()
           ).getAspectValue().longValue();
      }
      // should be TimeSpan.MIN_VALUE!
      return 0;
    }

    /**
     * Part of support for printing early-best-latest dates
     * for END_TIMEs with VScoringFunctions.
     */
    private static long getLateDate(ScoringFunction vsf) {
      Enumeration validRanges = getValidEndDateRanges(vsf);
      while (validRanges.hasMoreElements()) {
        AspectScoreRange range = 
          (AspectScoreRange)validRanges.nextElement();
        if (!validRanges.hasMoreElements())
          return ((AspectScorePoint)range.getRangeEndPoint()
              ).getAspectValue().longValue();
      }
      return TimeSpan.MAX_VALUE;
    }

    /* Needed for support of printing early-best-latest END_TIMEs */
    private static Calendar cal = java.util.Calendar.getInstance();

    /* Needed for support of printing early-best-latest END_TIMEs */
    private static Date endOfRange;
    static {
      cal.set(2200, 0, 0, 0, 0, 0);
      cal.set(Calendar.MILLISECOND, 0);
      endOfRange = (Date) cal.getTime();
    }

    /**
     * Part of support for printing early-best-latest dates
     * for END_TIMEs with VScoringFunctions.
     */
    private static Enumeration getValidEndDateRanges(ScoringFunction sf) {
      Enumeration validRanges = 
        sf.getValidRanges(
            TimeAspectValue.create(AspectType.END_TIME, 0l),
            TimeAspectValue.create(AspectType.END_TIME, endOfRange));
      return validRanges;
    }

    /**
     * printPlanElementDetails.
     *
     * PlanElements are always in the LogPlan and have UIDs, so we
     * don't need a "baseObj" (e.g. the Task that this PlanElement
     * is attached to).
     */
    private void printPlanElementDetails(PlanElement pe)
    {
      int peType = getItemType(pe);
      // show type
      if (peType != ITEM_TYPE_OTHER) {
        out.print(ITEM_TYPE_NAMES[peType]);
      } else {
        out.print(
            "<font color=red>");
        out.print(pe.getClass().getName());
        out.print(
            "</font>\n");
      }
      out.print("<ul>\n");
      // show UID
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "UID= ");
      UID peu = pe.getUID();
      out.print((peu != null) ? peu.toString() : "null");
      out.print(
          "</font>"+
          "</li>\n");
      // show task
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "Task= ");
      printLinkToLocalTask(pe.getTask());
      out.print(
          "</font>"+
          "</li>\n");
      // show plan
      Plan plan = pe.getPlan();
      if (plan != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Plan= ");
        out.print(plan.getPlanName());
        out.print(
            "</font>"+
            "</li>\n");
      }
      // show allocation results
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "Allocation Results</font>\n"+
          "<ul>\n");
      AllocationResult ar;
      if ((ar = pe.getEstimatedResult()) != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Estimated</font>");
        printAllocationResultDetails(ar);
        out.print(
            "</li>\n");
      }
      if ((ar = pe.getReportedResult()) != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Reported</font>");
        printAllocationResultDetails(ar);
        out.print(
            "</li>\n");
      }
      if ((ar = pe.getReceivedResult()) != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Received</font>");
        printAllocationResultDetails(ar);
        out.print(
            "</li>\n");
      }
      if ((ar = pe.getObservedResult()) != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Observed</font>");
        printAllocationResultDetails(ar);
        out.print(
            "</li>\n");
      }
      out.print(
          "</ul>"+
          "</li>\n");
      // show PE subclass information
      switch (peType) {
        case ITEM_TYPE_ALLOCATION:
          printAllocationDetails((Allocation)pe);
          break;
        case ITEM_TYPE_EXPANSION:
          printExpansionDetails((Expansion)pe);
          break;
        case ITEM_TYPE_AGGREGATION:
          printAggregationDetails((Aggregation)pe);
          break;
        case ITEM_TYPE_DISPOSITION:
          printDispositionDetails((Disposition)pe);
          break;
        case ITEM_TYPE_ASSET_TRANSFER:
          printAssetTransferDetails((AssetTransfer)pe);
          break;
        default: // other
          out.print(
              "<li>"+
              "<font color=red>"+
              "No details for class ");
          out.print(pe.getClass().getName());
          out.print("</font></li>");
          break;
      }
      out.print("</ul>\n");
      // link to XML view
      out.print("<font size=small color=mediumblue>");
      // planElements are always local
      printLinkToXML(pe, true);
      out.print("</font>");
    }

    /**
     * printAllocationResultDetails.
     */
    private void printAllocationResultDetails(AllocationResult ar)
    {
      out.print(
          "<ul>\n"+
          "<font size=small color=mediumblue>"+
          "<li>"+
          "isSuccess= ");
      // show isSuccess
      out.print(ar.isSuccess());
      out.print(
          "</li>"+
          "</font>\n"+
          "<font size=small color=mediumblue>"+
          "<li>"+
          "Confidence= ");
      // show confidence rating
      out.print(ar.getConfidenceRating());
      out.print(
          "</li>"+
          "</font>\n");
      // for all (type, result) pairs
      int[] arTypes = ar.getAspectTypes();
      double[] arResults = ar.getResult();
      for (int i = 0; i < arTypes.length; i++) {
        out.print(
            "<font size=small color=mediumblue>"+
            "<li>");
        // show type
        int arti = arTypes[i];
        out.print(AspectValue.aspectTypeToString(arti));
        out.print("= ");
        // show value
        double arri = arResults[i];
        switch (arti) {
          case AspectType.START_TIME:
          case AspectType.END_TIME:
          case AspectType.POD_DATE:
            // date
            out.print(
                getTimeString((long)arri));
            break;
          default:
            // other
            out.print(arri);
            break;
        }
        out.print(
            "</li>"+
            "</font>\n");
      }
      // show phased details
      if (ar.isPhased()) {
        out.print(
            "<font size=small color=mediumblue>"+
            "<li>"+
            "isPhased= true"+
            "</li>"+
            "</font>\n");
        // user likely not interested in phased results
      }
      out.print(
          "</ul>\n");
    }

    /**
     * printAllocationDetails.
     */
    private void printAllocationDetails(Allocation ac)
    {
      // show asset
      Asset asset = ac.getAsset();
      if (asset != null) {
        // link to allocated asset
        ClusterPG clusterPG = asset.getClusterPG();
        MessageAddress agentID;
        String remoteAgentID =
          ((((clusterPG = asset.getClusterPG()) != null) &&
            ((agentID = clusterPG.getMessageAddress()) != null)) ?
           agentID.toString() :
           null);
        boolean isRemoteAgent = (remoteAgentID != null);
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>");
        out.print(isRemoteAgent ? "Agent" : "Asset");
        out.print("= ");
        // allocations are always to an asset in the local LogPlan
        printLinkToLocalAsset(asset);
        out.print(
            "</font>"+
            "</li>\n");
        if (isRemoteAgent) {
          // link to task in other cluster
          String encRemoteAgentID = 
            support.encodeAgentName(remoteAgentID);
	  // TODO: We should get the Allocation task here, but the
	  // getAllocationTask() method has disappeared.
          // Task allocTask = ((AllocationforCollections)ac).getAllocationTask();
          Task allocTask = ((AllocationforCollections)ac).getTask();
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "AllocTask= ");
          printLinkToTask(
              allocTask, 
              encRemoteAgentID);
          out.print(
              "</font>"+
              "</li>\n");
        }
      } else {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Asset= </font>"+
            "<font color=red>null</font>"+
            "</li>\n");
      }
    }

    /**
     * printExpansionDetails.
     */
    private void printExpansionDetails(Expansion ex)
    {
      // link to child tasks
      out.print(
          "<li>"+
          "<font size=small color=black>"+
          "<i>Child Tasks</i>"+
          "</font>"+
          "<ol>\n");
      Enumeration en = ex.getWorkflow().getTasks();
      while (en.hasMoreElements()) {
        Task tsk = (Task)en.nextElement();
        out.print(
            "<font size=small color=mediumblue>"+
            "<li>");
        // expanded task is always local
        printLinkToLocalTask(tsk);
        out.print(
            "</li>"+
            "</font>");
      }
      out.print(
          "</ol>"+
          "</li>\n");
    }

    /**
     * printAggregationDetails.
     */
    private void printAggregationDetails(Aggregation agg)
    {
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "MPTask= ");
      Composition comp = agg.getComposition();
      if (comp != null) {
        // link to composed mp task
        Task compTask = comp.getCombinedTask();
        // composed task is always local
        printLinkToLocalTask(compTask);
      } else {
        out.print("<font color=red>null Composition</font>");
      }
      out.print(
          "</font>\n"+
          "</li>\n");
    }

    /**
     * printDispositionDetails.
     */
    private void printDispositionDetails(Disposition d)
    {
      // nothing to say?
      out.print(
          "<font size=small color=mediumblue>"+
          "Success= ");
      out.print(d.isSuccess());
      out.print("</font>\n");
    }

    /**
     * printAssetTransferDetails.
     */
    private void printAssetTransferDetails(AssetTransfer atrans)
    {
      // show attached asset
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "Asset= ");
      printLinkToAssetTransferAsset(atrans);
      out.print(
          "</font>"+
          "</li>\n");
      // show role
      Role role = atrans.getRole();
      if (role != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Role= ");
        out.print(role.getName());
        out.print(
            "</font>"+
            "</li>\n");
      }
      // show assignor
      MessageAddress assignor = atrans.getAssignor();
      if (assignor != null) {
        String name = assignor.toString();
        String encName = 
          ((name != null) ?
           (support.encodeAgentName(name)) :
           (null));
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Assignor= ");
        printLinkToTasksSummary(encName);
        out.print(
            "</font>"+
            "</li>\n");
      }
      // show assignee
      Asset assignee = atrans.getAssignee();
      if (assignee != null) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Assignee= ");
        // assignee asset is always in the local LogPlan
        printLinkToLocalAsset(assignee);
        out.print(
            "</font>"+
            "</li>\n");
      }
    }

    /**
     * printAssetDetails.
     */
    private void printAssetDetails(
        UniqueObject baseObj, Asset asset)
    {
      if (asset instanceof AssetGroup) {
        // recursive for AssetGroups!
        List assets = ((AssetGroup)asset).getAssets();
        int nAssets = ((assets != null) ? assets.size() : 0);
        out.print("AssetGroup[");
        out.print(nAssets);
        out.print("]:\n<ol>\n");
        for (int i = 0; i < nAssets; i++) {
          Asset as = (Asset)assets.get(i);
          out.print("<li>\n");
          if (as != null) {
            // recurse!
            //
            // unable to show XML for elements, so pass null baseObj
            printAssetDetails(null, as);
          } else {
            out.print("<font color=red>null</font>");
          }
          out.print("\n</li>\n");
        }
        out.print("</ol>\n");
        if (baseObj != null) {
            out.print("<font size=small color=mediumblue>");
            printLinkToAttachedXML(
                baseObj,
                asset,
                true);
        }
        return;
      }
      // if asset is an aggregate, info_asset is the
      // aggregate's asset which contains Type and Item info.
      Asset info_asset = asset;
      int quantity = 1;
      boolean isAggregateAsset = (asset instanceof AggregateAsset);
      if (isAggregateAsset) {
        do {
          AggregateAsset agg = (AggregateAsset)info_asset;
          quantity *= (int)agg.getQuantity();
          info_asset = agg.getAsset();
        } while (info_asset instanceof AggregateAsset);
        if (info_asset == null) {
          // bad!  should throw exception, but I doubt this will
          // ever happen...
          info_asset = asset;
        }
      }
      out.print("<ul>\n");
      if (isAggregateAsset) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "Quantity= ");
        // show quantity
        out.print(quantity);
        out.print(
            "</font>"+
            "</li>\n");
      } else {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "UID= ");
        // show UID
        UID u = asset.getUID();
        String foundUID = ((u != null) ? u.toString() : "null");
        out.print(foundUID);
        out.print(
            "</font>"+
            "</li>\n");
      }
      // show class
      out.print(
          "<li>"+
          "<font size=small color=mediumblue>"+
          "Class= ");
      out.print(info_asset.getClass().getName());
      out.print(
          "</font>"+
          "</li>\n");
      // show type id info
      TypeIdentificationPG tipg = info_asset.getTypeIdentificationPG();
      if (tipg != null) {
        String tiid = tipg.getTypeIdentification();
        if (tiid != null) {
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "TypeID= ");
          out.print(tiid);
          out.print(
              "</font>"+
              "</li>");
        }
        String tin = tipg.getNomenclature();
        if (tin != null) {
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "TypeNomenclature= ");
          out.print(tin);
          out.print(
              "</font>"+
              "</li>");
        }
        String tiati = tipg.getAlternateTypeIdentification();
        if (tiati != null) {
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "AlternateTypeID= ");
          out.print(tiati);
          out.print(
              "</font>"+
              "</li>");
        }
      } else {
        out.print(
            "<li>"+
            "<font color=red>"+
            "TypeID missing"+
            "</font>"+
            "</li>\n");
      }
      // show item id
      ItemIdentificationPG iipg = info_asset.getItemIdentificationPG();
      if (iipg != null) {
        String iiid = iipg.getItemIdentification();
        if (iiid != null) {
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "ItemID= ");
          out.print(iiid);
          out.print(
              "</font>"+
              "</li>");
        }
        String iin = iipg.getNomenclature();
        if (iin != null) {
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "ItemNomenclature= ");
          out.print(iin);
          out.print(
              "</font>"+
              "</li>");
        }
        String iiati = iipg.getAlternateItemIdentification();
        if (iiati != null) {
          out.print(
              "<li>"+
              "<font size=small color=mediumblue>"+
              "AlternateItemID= ");
          out.print(iiati);
          out.print(
              "</font>"+
              "</li>");
        }
      } else {
        out.print(
            "<li>"+
            "<font color=red>"+
            "ItemID missing"+
            "</font>"+
            "</li>\n");
      }
      // show role schedule
      RoleSchedule rs;
      Schedule sc;
      if (((rs = asset.getRoleSchedule()) != null) &&
          ((sc = rs.getAvailableSchedule()) != null) &&
          !sc.isEmpty() ) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "RoleSchedule<br>\n"+
            "Start= ");
        out.print(getTimeString(sc.getStartTime()));
        out.print("<br>End= ");
        out.print(getTimeString(sc.getEndTime()));
        out.print("<br>\n");
        Enumeration rsEn = rs.getRoleScheduleElements();
        if (rsEn.hasMoreElements()) {
          out.print(
              "RoleScheduleElements<br>\n"+
              "<ol>\n");
          do {
            PlanElement pe = (PlanElement)rsEn.nextElement();
            out.print("<li>");
            // planElements are always local
            printLinkToPlanElement(pe);
            out.print("</li>\n");
          } while (rsEn.hasMoreElements());
          out.print("</ol>\n");
        } else {
          out.print("RoleScheduleElements: none<br>\n");
        }
        Iterator iterator = new ArrayList(sc).iterator();
        if (iterator.hasNext()) {
          out.print(
              "AvailableScheduleElements<br>\n"+
              "<ol>\n");
          while (iterator.hasNext()) {
            ScheduleElement se = (ScheduleElement)iterator.next();
            out.print(
                "<li>Start= ");
            out.print(getTimeString(se.getStartTime()));
            out.print("<br>End= ");
            out.print(getTimeString(se.getEndTime()));
            out.print("</li>\n");
          } 
          out.print("</ol>\n");
        } else {
          out.print("AvailableScheduleElements: none<br>\n");
        }
        out.print(
            "</font>"+
            "</li>\n");
      }
      // show location schedule
      LocationSchedulePG locSchedPG;
      Schedule locSched;
      if (((locSchedPG = asset.getLocationSchedulePG()) != null) &&
          ((locSched = locSchedPG.getSchedule()) != null) &&
          (!(locSched.isEmpty()))) {
        out.print(
            "<li>"+
            "<font size=small color=mediumblue>"+
            "LocationSchedule<br>\n"+
            "Start= ");
        out.print(getTimeString(locSched.getStartTime()));
        out.print("<br>End= ");
        out.print(getTimeString(locSched.getEndTime()));
        out.print("<br>\n");
        Enumeration locSchedEn = locSched.getAllScheduleElements();
        if (locSchedEn.hasMoreElements()) {
          out.print(
              "LocationScheduleElements<br>\n"+
              "<ol>\n");
          do {
            ScheduleElement se = (ScheduleElement)locSchedEn.nextElement();
            out.print(
                "<li>Start= ");
            out.print(getTimeString(se.getStartTime()));
            out.print("<br>End= ");
            out.print(getTimeString(se.getEndTime()));
            if (se instanceof LocationScheduleElement) {
              LocationScheduleElement lse = (LocationScheduleElement)se;
              Location loc = lse.getLocation();
              if (loc != null) {
                out.print("<br>Location= \"");
                out.print(loc);
                out.print("\"");
              }
            }
            out.print("</li>\n");
          } while (locSchedEn.hasMoreElements());
          out.print("</ol>\n");
        } else {
          out.print("LocationScheduleElements: none<br>\n");
        }
        out.print(
            "</font>"+
            "</li>\n");
      }
      // PGs?
      out.print("</ul>");
      if (baseObj != null) {
        out.print("<font size=small color=mediumblue>");
        printLinkToAttachedXML(
              baseObj,
              asset,
              true);
      } else {
        // likely recursed on an AssetGroup, and the top-level group
        //   had a "View XML" link.
      }
    }

    /**
     * printAssetTableRow.
     *
     * Asset that is in the local LogPlan and has a UID.  Treat this
     * as an Asset attached to itself.
     */
    private void printAssetTableRow(Asset asset)
    {
      printAttachedAssetTableRow(
          asset,
          asset,
          MODE_ASSET_DETAILS);
    }

    /**
     * printTaskDirectObjectTableRow.
     */
    private void printTaskDirectObjectTableRow(Task task)
    {
      printAttachedAssetTableRow(
          task,
          ((task != null) ? task.getDirectObject() : null),
          MODE_TASK_DIRECT_OBJECT_DETAILS);
    }

    /**
     * printAttachedAssetTableRow.
     * <p>
     * Print asset information in three table columns:<br>
     * <ol>
     *   <li>UID</li>
     *   <li>TypeID</li>
     *   <li>ItemID</li>
     *   <li>Quantity</li>
     * </ol>
     * Be sure to have a corresponding table!
     *
     * @see #printTaskDirectObjectTableRow
     */
    private void printAttachedAssetTableRow(
        UniqueObject baseObj, Asset asset, int baseMode)
    {
      if ((baseObj == null) ||
          (asset == null)) {
        out.print(
            "<td colspan=4>"+
            "<font color=red>null</font>"+
            "</td>\n");
      } else if (asset instanceof AssetGroup) {
        // link to asset group
        //   "UID" of the baseObj, and a link using that UID
        //   "TypeID" is a bold "AssetGroup"
        //   "ItemID" is "N/A"
        //   "Quantity" is the number of items in the group
        out.print("<td>");
        printLinkToAttachedAsset(baseObj, asset, baseMode);
        out.print(
            "</td>\n"+
            "<td>"+
            "<b>AssetGroup</b>"+
            "</td>\n"+
            "<td>"+
            "N/A"+
            "</td>\n"+
            "<td align=right>");
        List assets = ((AssetGroup)asset).getAssets();
        int nAssets = ((assets != null) ? assets.size() : 0);
        out.print(nAssets);
        out.print(
            "</td>\n");
      } else {
        // if asset is an aggregate, info_asset is the
        // aggregate's asset which contains Type and Item info.
        Asset info_asset;
        int quantity;
        if (asset instanceof AggregateAsset) {
          info_asset = asset;
          quantity = 1;
          do {
            AggregateAsset agg = (AggregateAsset)info_asset;
            quantity *= (int)agg.getQuantity();
            info_asset = agg.getAsset();
          } while (info_asset instanceof AggregateAsset);
          if (info_asset == null) {
            out.print(
                "<td colspan=4>"+
                "<font color=red>null</font>"+
                "</td>\n");
            return;
          }
        } else {
          info_asset = asset;
          if (asset instanceof AssetGroup) {
            List assets = ((AssetGroup)asset).getAssets();
            quantity = ((assets != null) ? assets.size() : 0);
          } else {
            quantity = 1;
          }
        }
        // link to asset
        out.print("<td>");
        printLinkToAttachedAsset(baseObj, asset, baseMode);
        out.print(
            "</td>\n"+
            "<td>");
        // show type id
        TypeIdentificationPG tipg = info_asset.getTypeIdentificationPG();
        if (tipg != null) {
          out.print(
              tipg.getTypeIdentification());
        } else {
          out.print("<font color=red>missing typeID</font>");
        }
        out.print(
            "</td>\n"+
            "<td>");
        // show item id
        ItemIdentificationPG iipg = info_asset.getItemIdentificationPG();
        if (iipg != null) {
          out.print(
              iipg.getItemIdentification());
        } else {
          out.print("<font color=red>missing itemID</font>");
        }
        out.print(
            "</td>\n"+
            "<td align=right>");
        // show quantity
        out.print(quantity);
        out.print("</td>\n");
      }
    }

    /**
     * printXMLizableDetails.
     * <p>
     * Prints XML for given XMLizable Object.
     * <p>
     * Considered embedding some Applet JTree viewer, e.g.<br>
     * <code>ui.planviewer.XMLViewer</code>
     * but would need separate Applet code.
     * <p>
     * Also considered using some nifty javascript XML tree viewer, e.g.<br>
     * <code>http://developer.iplanet.com/viewsource/smith_jstree/smith_jstree.html</code><br>
     * but would take some work...
     * <p>
     * @param printAsHTML uses XMLtoHTMLOutputStream to pretty-print the XML
     */
    private void printXMLizableDetails(
        Object xo, boolean printAsHTML)
    {
      try {
        // convert to XML
        Document doc = new DocumentImpl();
        Element element = XMLize.getPlanObjectXML(xo, doc);
        doc.appendChild(element);

        // print to output
        if (printAsHTML) {
          OutputFormat format = new OutputFormat();
          format.setPreserveSpace(false);
          format.setIndent(2);

          PrintWriter pout = new PrintWriter(new XMLtoHTMLOutputStream(out));
          XMLSerializer serializer = new XMLSerializer(pout, format);
          out.print("<pre>\n");
          serializer.serialize(doc);
          out.print("\n</pre>\n");
          pout.flush();
        } else {
          OutputFormat format = new OutputFormat();
          format.setPreserveSpace(true);

          PrintWriter pout = new PrintWriter(out);
          XMLSerializer serializer = new XMLSerializer(pout, format);
          serializer.serialize(doc);
          pout.flush();
        }
      } catch (Exception e) {
        if (printAsHTML) {
          out.print("\nException!\n\n");
          e.printStackTrace(out);
        }
      }
    }

    /** END PRINT ROUTINES **/

    /** BEGIN PRINTLINK ROUTINES **/

    /**
     * print link to task summary at this cluster.
     */

    private void printLinkToTasksSummary()
    {
      printLinkToTasksSummary(
          support.getEncodedAgentName());
    }

    /**
     * print link to task summary for given cluster
     */
    private void printLinkToTasksSummary(
        String encodedAgentName)
    {
      if (encodedAgentName != null) {
        out.print("<a href=\"/$");
        // link to cluster
        out.print(encodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_TASKS_SUMMARY);
        out.print("\" target=\"tablesFrame\">");
        out.print(support.getEncodedAgentName());
        out.print(
            "</a>");
      } else {
        out.print("<font color=red>Unknown cluster</font>");
      }
    }

    /** simple flags for parameter checking **/
    private static final byte _FLAG_LIMIT   = (1 << 0);
    private static final byte _FLAG_VERB    = (1 << 1);
    private static final byte _FLAG_VERBOSE = (1 << 2);
    private static final byte _FLAG_SORT    = (1 << 3);

    /**
     * printLinkToAllTasks for the local cluster.
     */
    private void printLinkToAllTasks(
        String verb, int limit, int numTasks, boolean verbose)
    {
      printLinkToAllTasks(
          support.getEncodedAgentName(),
          verb, limit, numTasks, verbose);
    }

    /**
     * printLinkToAllTasks.
     */
    private void printLinkToAllTasks(
        String encodedAgentName,
        String verb, int limit, int numTasks, boolean verbose)
    {
      if (encodedAgentName != null) {
        out.print("<a href=\"/$");
        out.print(encodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_ALL_TASKS);
        // set flags
        byte flags = 0;
        if (limit > 0) {
          out.print(
              "&"+
              LIMIT+
              "=true");
          flags |= _FLAG_LIMIT;
        }
        if (verb != null) {
          out.print(
              "&"+
              VERB+
              "=");
          out.print(verb);
          flags |= _FLAG_VERB;
        }
        if (verbose) {
          flags |= _FLAG_VERBOSE;
        }
	if (sortByUID)
	  out.print ("&" + SORT_BY_UID + "=true");

        out.print("\" target=\"tablesFrame\">");
        // print over-customized output .. make parameter?
        switch (flags) {
          case (_FLAG_LIMIT):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b>");
            break;
          case (_FLAG_LIMIT | _FLAG_VERBOSE):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b> of <b>");
            out.print(numTasks);
            out.print("</b> Tasks at ");
            out.print(encodedAgentName);
            break;
          case (_FLAG_LIMIT | _FLAG_VERB):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b>");
            break;
          case (_FLAG_LIMIT | _FLAG_VERB | _FLAG_VERBOSE):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b> of <b>");
            out.print(numTasks);
            out.print("</b> Tasks with verb ");
            out.print(verb);
            out.print("at ");
            out.print(encodedAgentName);
            break;
          case (_FLAG_VERB):
            out.print(verb);
            break;
          case (_FLAG_VERB | _FLAG_VERBOSE):
            out.print("View all <b>");
            out.print(numTasks);
            out.print("</b> Tasks with verb ");
            out.print(verb);
            out.print(" at ");
            out.print(encodedAgentName);
            break;
          default:
          case (0):
          case (_FLAG_VERBOSE):
            out.print("View all <b>");
            out.print(numTasks);
            out.print("</b> Tasks at ");
            out.print(support.getEncodedAgentName());
            break;
        }
        out.print("</a>");
      } else {
        out.print("<font color=red>Unknown cluster</font>");
      }
    }

    /**
     * printLinkToAllPlanElements for the local cluster.
     */
    private void printLinkToAllPlanElements(
        int limit, int numPlanElements, boolean verbose)
    {
      printLinkToAllPlanElements(
          support.getEncodedAgentName(),
          limit, numPlanElements, verbose);
    }

    /**
     * printLinkToAllPlanElements.
     */
    private void printLinkToAllPlanElements(
        String encodedAgentName,
        int limit, int numPlanElements, boolean verbose)
    {
      if (encodedAgentName != null) {
        out.print("<a href=\"/$");
        out.print(encodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_ALL_PLAN_ELEMENTS);
        // set flags
        byte flags = 0;
        if (limit > 0) {
          out.print(
              "&"+
              LIMIT+
              "=true");
          flags |= _FLAG_LIMIT;
        }
        if (verbose) {
          flags |= _FLAG_VERBOSE;
        }
        out.print("\" target=\"tablesFrame\">");
        // print over-customized output .. make parameter?
        switch (flags) {
          case (_FLAG_LIMIT):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b>");
            break;
          case (_FLAG_LIMIT | _FLAG_VERBOSE):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b> of <b>");
            out.print(numPlanElements);
            out.print("</b> PlanElements at ");
            out.print(encodedAgentName);
            break;
          default:
          case (0):
          case (_FLAG_VERBOSE):
            out.print("View all <b>");
            out.print(numPlanElements);
            out.print("</b> PlanElements at ");
            out.print(encodedAgentName);
            break;
        }
        out.print("</a>");
      } else {
        out.print("<font color=red>Unknown cluster</font>");
      }
    }

    /**
     * printLinkToAllAssets for the local cluster.
     */
    private void printLinkToAllAssets(
        int limit, int numAssets, boolean verbose)
    {
      printLinkToAllAssets(
          support.getEncodedAgentName(),
          limit, numAssets, verbose);
    }

    /**
     * printLinkToAllAssets.
     */
    private void printLinkToAllAssets(
        String encodedAgentName,
        int limit, int numAssets, boolean verbose)
    {
      if (encodedAgentName != null) {
        out.print("<a href=\"/$");
        out.print(encodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_ALL_ASSETS);
        // set flags
        byte flags = 0;
        if (limit > 0) {
          out.print(
              "&"+
              LIMIT+
              "=true");
          flags |= _FLAG_LIMIT;
        }
        if (verbose) {
          flags |= _FLAG_VERBOSE;
        }
        out.print("\" target=\"tablesFrame\">");
        // print over-customized output .. make parameter?
        switch (flags) {
          case (_FLAG_LIMIT):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b>");
            break;
          case (_FLAG_LIMIT | _FLAG_VERBOSE):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b> of <b>");
            out.print(numAssets);
            out.print("</b> Assets at ");
            out.print(encodedAgentName);
            break;
          default:
          case (0):
          case (_FLAG_VERBOSE):
            out.print("View all <b>");
            out.print(numAssets);
            out.print("</b> Assets at ");
            out.print(encodedAgentName);
            break;
        }
        out.print("</a>");
      } else {
        out.print("<font color=red>Unknown cluster</font>");
      }
    }

    /**
     * printLinkToAllUniqueObjects for the local cluster.
     */
    private void printLinkToAllUniqueObjects(
        int limit, int numUniqueObjects, boolean verbose)
    {
      printLinkToAllUniqueObjects(
          support.getEncodedAgentName(),
          limit, numUniqueObjects, verbose);
    }

    /**
     * printLinkToAllUniqueObjects.
     */
    private void printLinkToAllUniqueObjects(
        String encodedAgentName,
        int limit, int numUniqueObjects, boolean verbose)
    {
      if (encodedAgentName != null) {
        out.print("<a href=\"/$");
        out.print(encodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_ALL_UNIQUE_OBJECTS);
        // set flags
        byte flags = 0;
        if (limit > 0) {
          out.print(
              "&"+
              LIMIT+
              "=true");
          flags |= _FLAG_LIMIT;
        }
        if (verbose) {
          flags |= _FLAG_VERBOSE;
        }
        out.print("\" target=\"tablesFrame\">");
        // print over-customized output .. make parameter?
        switch (flags) {
          case (_FLAG_LIMIT):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b>");
            break;
          case (_FLAG_LIMIT | _FLAG_VERBOSE):
            out.print("View first <b>");
            out.print(limit);
            out.print("</b> of <b>");
            out.print(numUniqueObjects);
            out.print("</b> UniqueObjects at ");
            out.print(encodedAgentName);
            break;
          default:
          case (0):
          case (_FLAG_VERBOSE):
            out.print("View all <b>");
            out.print(numUniqueObjects);
            out.print("</b> UniqueObjects at ");
            out.print(encodedAgentName);
            break;
        }
        out.print("</a>");
      } else {
        out.print("<font color=red>Unknown cluster</font>");
      }
    }

    /**
     * printLinkToParentTask.
     * <p>
     * Get task's parent before linking.
     */
    private void printLinkToParentTask(Task task)
    {
      UID ptU;
      String ptUID;
      if (task == null) {
        out.print("<font color=red>null</font>");
      } else if (((ptU = task.getParentTaskUID()) == null) ||
          ((ptUID = ptU.toString()) == null)) {
        out.print("<font color=red>parent not unique</font>");
      } else {
        MessageAddress tClusterID = task.getSource();
        String ptEncodedAgentName;
        if ((tClusterID == null) ||
            ((ptEncodedAgentName = tClusterID.toString()) == null)) {
          ptEncodedAgentName = support.getEncodedAgentName();
        } else {
          ptEncodedAgentName = support.encodeAgentName(ptEncodedAgentName);
        }
        out.print("<a href=\"/$");
        out.print(ptEncodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_TASK_DETAILS+
            "&"+
            ITEM_UID+
            "=");
        out.print(encodeUID(ptUID));
        out.print("\" target=\"itemFrame\">");
        out.print(ptUID);
        out.print("</a>");
      }
    }

    /**
     * printLinkToLocalTask.
     * <p>
     * Tasks that stay in the current cluster.
     */
    private void printLinkToLocalTask(Task task)
    {
      printLinkToTask(
          task, 
          support.getEncodedAgentName());
    }

    /**
     * printLinkToTask.
     * <p>
     * This method attempts to works around task forwarding across
     * clusters in the "Down" sense, i.e. allocations.
     */
    private void printLinkToTask(
        Task task, 
        String atEncodedAgentName)
    {
      UID taskU;
      String taskUID;
      if (task == null) {
        out.print("<font color=red>null</font>");
      } else if (((taskU = task.getUID()) == null) ||
          ((taskUID = taskU.toString()) == null)) {
        out.print("<font color=red>not unique</font>");
      } else {
        out.print("<a href=\"/$");
        out.print(atEncodedAgentName);
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_TASK_DETAILS+
            "&"+
            ITEM_UID+
            "=");
        out.print(encodeUID(taskUID));
        out.print("\" target=\"itemFrame\">");
        out.print(taskUID);
        out.print("</a>");
      }
    }

    /**
     * printLinkToPlanElement.
     * <p>
     * PlanElements stay in their cluster
     */
    private void printLinkToPlanElement(PlanElement pe)
    {
      UID peU;
      String peUID;
      if (pe == null) {
        out.print("<font color=red>null</font>\n");
      } else if (((peU = pe.getUID()) == null) ||
          ((peUID = peU.toString()) == null)) {
        out.print("<font color=red>not unique</font>\n");
      } else {
        out.print("<a href=\"/$");
        out.print(support.getEncodedAgentName());
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            MODE_PLAN_ELEMENT_DETAILS+
            "&"+
            ITEM_UID+
            "=");
        out.print(encodeUID(peUID));
        out.print("\" target=\"itemFrame\">");
        out.print(peUID);
        out.print("</a>");
      }
    }

    /**
     * printLinkToLocalAsset.
     * <p>
     * Asset that is in the local LogPlan and has a UID.  Treat this
     * as an Asset attached to itself.
     **/
    private void printLinkToLocalAsset(Asset asset)
    {
      printLinkToAttachedAsset(
          asset, 
          asset,
          MODE_ASSET_DETAILS);
    }

    /**
     * printLinkToTaskDirectObject.
     **/
    private void printLinkToTaskDirectObject(Task task)
    {
      printLinkToAttachedAsset(
          task, 
          ((task != null) ? task.getDirectObject() : null),
          MODE_TASK_DIRECT_OBJECT_DETAILS);
    }

    /**
     * printLinkToAssetTransferAsset.
     **/
    private void printLinkToAssetTransferAsset(AssetTransfer atrans)
    {
      printLinkToAttachedAsset(
          atrans, 
          ((atrans != null) ? atrans.getAsset() : null),
          MODE_ASSET_TRANSFER_ASSET_DETAILS);
    }

    /**
     * printLinkToAttachedAsset.
     *
     * @see #printLinkToTaskDirectObject
     * @see #printLinkToAssetTransferAsset
     **/
    private void printLinkToAttachedAsset(
        UniqueObject baseObj, Asset asset, 
        int baseMode)
    {
      UID baseObjU;
      String baseObjUID;
      if ((baseObj == null) ||
          (asset == null)) {
        out.print("<font color=red>null</font>");
      } else if (((baseObjU = baseObj.getUID()) == null) ||
          ((baseObjUID = baseObjU.toString()) == null)) {
        out.print("<font color=red>not unique</font>");
      } else {
        out.print("<a href=\"/$");
        out.print(support.getEncodedAgentName());
        out.print(support.getPath());
        out.print(
            "?"+
            MODE+
            "="+
            baseMode+
            "&"+
            ITEM_UID+
            "=");
        out.print(encodeUID(baseObjUID));
        out.print("\" target=\"itemFrame\">");
        String assetName;
        if (asset == baseObj) {
          // asset it it's own base
          assetName = baseObjUID;
        } else {
          UID assetU;
          // asset attached to the base UniqueObject
          if (((assetU = asset.getUID()) == null) ||
              ((assetName = assetU.toString()) == null)) {
            if (asset instanceof AggregateAsset) {
              assetName = "Non-UID Aggregate";
            } else if (asset instanceof AssetGroup) {
              assetName = "Non-UID Group";
            } else {
              assetName = "Non-UID "+asset.getClass().getName();
            }
          }
        }
        out.print(assetName);
        out.print("</a>");
      }
    }

    /**
     * printLinkToXML.
     * <p>
     * XML objects stay in cluster.
     **/
    private void printLinkToXML(
        UniqueObject uo, boolean asHTML)
    {
      if (uo != null) {
        // link to HTML-encoded XML view
        printLinkToAttachedXML(
            uo,
            uo,
            asHTML);
      } else {
        out.print("<font color=red>null</font>");
      }
    }

    /**
     * printLinkToXML.
     * <p>
     * XML objects stay in cluster.
     **/
    private void printLinkToXML(
        Object xo, boolean asHTML)
    {
      if (xo instanceof UniqueObject) {
        // link to HTML-encoded XML view
        printLinkToAttachedXML(
            (UniqueObject)xo,
            xo,
            asHTML);
      } else if (xo == null) {
        out.print("<font color=red>null</font>");
      } else {
        // asset not XMLizable
        out.print("<font color=red>");
        out.print(xo.getClass().getName());
        out.print(" not a UniqueObject</font>");
      }
    }

    /**
     * printLinkToAttachedXML.
     **/
    private void printLinkToAttachedXML(
        UniqueObject baseObj, Object xo, 
        boolean asHTML)
    {
      UID baseObjU;
      String baseObjUID;
      if ((xo == null) ||
          (baseObj == null) ||
          ((baseObjU = baseObj.getUID()) == null) ||
          ((baseObjUID = baseObjU.toString()) == null)) {
        if (asHTML) {
          out.print("<font color=red>Unable to view XML</font>\n");
        } else {
          out.print("<font color=red>Raw XML unavailable</font>\n");
        }
      } else {
        String encBaseObjUID = encodeUID(baseObjUID);
        String baseA = "<a href=\"/$" + support.getEncodedAgentName() +
          support.getPath() + "?" + ITEM_UID + "=" +
          encBaseObjUID + "&" + MODE + "=";
        String endA = "\" target=\"xml_" + encBaseObjUID +
          "_page\">";

        int mode =
          ((xo == baseObj) ?
           (asHTML ? 
            MODE_XML_HTML_DETAILS :
            MODE_XML_RAW_DETAILS) :
           (asHTML ? 
            MODE_XML_HTML_ATTACHED_DETAILS :
            MODE_XML_RAW_ATTACHED_DETAILS));
        out.print(baseA);
        out.print(mode);
        out.print(endA);
        String xoName;
        if (xo == baseObj) {
          xoName = baseObjUID;
        } else {
          if (xo instanceof UniqueObject) {
            UID xoU;
            if (((xoU = ((UniqueObject)xo).getUID()) == null) ||
                ((xoName = xoU.toString()) == null)) {
              if (xo instanceof AggregateAsset) {
                xoName = "Non-UID Aggregate";
              } else if (xo instanceof AssetGroup) {
                xoName = "Non-UID Group";
              } else {
                xoName = "Non-UID "+xo.getClass().getName();
              }
            }
          } else {
            xoName = "Non-UniqueObject "+xo.getClass().getName();
          }
        }
        if (asHTML) {
          out.print("View XML for ");
          out.print(xoName);
        } else {
          out.print("Raw XML for ");
          out.print(xoName);
          out.print("</a>\n<br>\n");
          out.print(baseA);
          out.print(MODE_EDIT_FIELDS);
          out.print(endA);
          out.print("Edit simple fields for ");
          out.print(xoName);
          out.print("</a><br>\n");
          out.print(baseA);
          out.print(MODE_ENTER_CODE);
          out.print(endA);
          out.print("Execute code against ");
          out.print(xoName);
          out.print("</a>\n<br>\n");
          out.print(baseA);
          out.print(MODE_LOAD_SAVE_OBJECT);
          out.print(endA);
          out.print("Save UniqueObject ");
          out.print(xoName);
        }
        out.print("</a><br>\n");
      }
    }

    /** END PRINTLINK ROUTINES **/

    /** BEGIN UTILITY PARSERS **/

    /**
     * printObject.
     * <p>
     * Currently used to print Preposition.getIndirectObject()
     * <p>
     * recursive for AssetGroups!
     */
    private void printObject(Object io)
    {
      try {
        if (io == null) {
          out.print("<font color=red>null</font>");
        } else if (io instanceof String) {
          out.print((String)io);
        } else if (io instanceof Location) {
          out.print("Location: \"");
          out.print(io.toString());
          out.print("\"");
        } else if (io instanceof Asset) {
          Asset as = (Asset)io;
          out.print("Asset: \"");
          TypeIdentificationPG tipg;
          String tiNomen;
          if (((tipg = as.getTypeIdentificationPG()) != null) &&
              ((tiNomen = tipg.getNomenclature()) != null)) {
            out.print(tiNomen);
          }
          out.print("(asset type=");
          out.print(as.getClass().getName());
          out.print(", asset uid=");
          UID asu;
          String uid;
          if (((asu = as.getUID()) != null) &&
              ((uid = asu.toString()) != null)) {
            out.print(uid);
          } else {
            out.print("None");
          }
          out.print(")\"");
        } else if (io instanceof Schedule) {
          out.print(io.getClass().getName());
        } else if (io instanceof MessageAddress) {
          out.print("CID: \"");
          out.print(((MessageAddress)io).toString());
          out.print("\"");
        } else if (io instanceof AssetTransfer) {
          out.print("AssetTransfer: \"");
          out.print(((AssetTransfer)io).getAsset().getName());
          out.print("\"");
        } else if (io instanceof AssetAssignment) {
          out.print("AssetAssignment: \"");
          out.print(((AssetAssignment)io).getAsset().getName());
          out.print("\"");
        } else if (io instanceof AssetGroup) {
          out.print("AssetGroup: \"[");
          List assets = ((AssetGroup)io).getAssets();
          for (int i = 0; i < assets.size(); i++) {
            Asset as = (Asset)assets.get(i);
            // recursive!
            printObject(as);
          }
          out.print("]\"");
        } else if (io instanceof AbstractMeasure) {
          String clName = ((AbstractMeasure)io).getClass().getName();
          int i = clName.lastIndexOf('.');
          if (i > 0) {
            clName = clName.substring(i+i);
          }
          out.print(clName);
          out.print(": ");
          out.print(io.toString());
        } else { 
          out.print(io.getClass().getName()); 
          out.print(": ");
          out.print(io.toString());
        }
      } catch (Exception e) {
        out.print("<font color=red>invalid</font>");
      }
    }

    /** END UTILITY PARSERS **/

    /** BEGIN BLACKBOARD SEARCHERS **/

    private UnaryPredicate getUniqueObjectWithUIDPred(
        final String uidFilter) 
    {
      final UID findUID = UID.toUID(uidFilter);
      return new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof UniqueObject) {
            UID u = ((UniqueObject)o).getUID();
            return 
              findUID.equals(u);
          }
          return false;
        }
      };
    }

    private UnaryPredicate getTaskPred() 
    {
      return new UnaryPredicate() {
        public boolean execute(Object o) {
          return (o instanceof Task);
        }
      };
    }

    private UnaryPredicate getTaskWithVerbPred(final Verb v) 
    {
      return new UnaryPredicate() {
        public boolean execute(Object o) {
          return ((o instanceof Task) &&
              v.equals(((Task)o).getVerb()));
        }
      };
    }

    private UnaryPredicate getPlanElementPred() 
    {
      return new UnaryPredicate() {
        public boolean execute(Object o) {
          return (o instanceof PlanElement);
        }
      };
    }

    private UnaryPredicate getAssetPred() 
    {
      return new UnaryPredicate() {
        public boolean execute(Object o) {
          return (o instanceof Asset);
        }
      };
    }

    private UnaryPredicate getUniqueObjectPred() 
    {
      return new UnaryPredicate() {
        public boolean execute(Object o) {
          return (o instanceof UniqueObject);
        }
      };
    }

    private Collection searchUsingPredicate(
        UnaryPredicate pred) 
    {
      Collection col = support.queryBlackboard(pred);
      if (sortByUID && 
          (col.size() > 1)) {
        Object[] a = col.toArray();
        Arrays.sort(a, THE_ONLY_UID_COMPARATOR);
        return Arrays.asList(a);
      } else {
        return col;
      }
    }

    private static final Comparator THE_ONLY_UID_COMPARATOR = new UIDComparator ();

    private static class UIDComparator implements Comparator {
      public int compare (Object first, Object second) {
	if (first instanceof UniqueObject) {
	  if (second instanceof UniqueObject) {
	    // return the usual UID compare
	    UID u1 = ((UniqueObject) first).getUID();
	    UID u2 = ((UniqueObject) second).getUID();
	    return u1.compareTo(u2);
	  } else {
	    return -1;
	  }
	} else if (second instanceof UniqueObject) {
	  return 1;
	} else {
	  return 0;
	}
      }
    }

    private UniqueObject findUniqueObjectWithUID(
        final String itemUID)
    {
      if (itemUID == null) {
        // missing UID
        return null;
      }
      Collection col = 
        searchUsingPredicate(
            getUniqueObjectWithUIDPred(itemUID));
      if (col.size() < 1) {
        // item not found
        return null;
      }
      // take first match
      Iterator iter = col.iterator();
      UniqueObject uo = (UniqueObject)iter.next();
      if (DEBUG) {
        if (iter.hasNext()) {
          System.err.println("Multiple matches for "+itemUID+"?");
        }
      }
      return uo;
    }

    private Collection findAllTasks()
    {
      return 
        searchUsingPredicate(getTaskPred());
    }

    private Collection findTasksWithVerb(
        final String verbFilter)
    {
      if (verbFilter == null) {
        // missing verb
        return null;
      }
      Verb v = Verb.getVerb(verbFilter);
      return 
        searchUsingPredicate(
            getTaskWithVerbPred(v));
    }

    private Collection findAllPlanElements()
    {
      return 
        searchUsingPredicate(
            getPlanElementPred());
    }

    private Collection findAllAssets()
    {
      return 
        searchUsingPredicate(
            getAssetPred());
    }

    private Collection findAllUniqueObjects()
    {
      return 
        searchUsingPredicate(
            getUniqueObjectPred());
    }

    /** END BLACKBOARD SEARCHERS **/

    /** BEGIN MISC UTILITIES **/

    /**
     * Item type codes to show interface name instead of "*Impl".
     **/
    private static final int ITEM_TYPE_ALLOCATION     = 0;
    private static final int ITEM_TYPE_EXPANSION      = 1;
    private static final int ITEM_TYPE_AGGREGATION    = 2;
    private static final int ITEM_TYPE_DISPOSITION    = 3;
    private static final int ITEM_TYPE_ASSET_TRANSFER = 4;
    private static final int ITEM_TYPE_TASK           = 5;
    private static final int ITEM_TYPE_ASSET          = 6;
    private static final int ITEM_TYPE_WORKFLOW       = 7;
    private static final int ITEM_TYPE_OTHER          = 8;
    private static String[] ITEM_TYPE_NAMES;
    static {
      ITEM_TYPE_NAMES = new String[(ITEM_TYPE_OTHER+1)];
      ITEM_TYPE_NAMES[ITEM_TYPE_ALLOCATION     ] = "Allocation";
      ITEM_TYPE_NAMES[ITEM_TYPE_EXPANSION      ] = "Expansion";
      ITEM_TYPE_NAMES[ITEM_TYPE_AGGREGATION    ] = "Aggregation";
      ITEM_TYPE_NAMES[ITEM_TYPE_DISPOSITION    ] = "Disposition";
      ITEM_TYPE_NAMES[ITEM_TYPE_ASSET_TRANSFER ] = "AssetTransfer";
      ITEM_TYPE_NAMES[ITEM_TYPE_TASK           ] = "Task";
      ITEM_TYPE_NAMES[ITEM_TYPE_ASSET          ] = "Asset";
      ITEM_TYPE_NAMES[ITEM_TYPE_WORKFLOW       ] = "Workflow";
      ITEM_TYPE_NAMES[ITEM_TYPE_OTHER          ] = null;
    }

    /**
     * getItemType.
     * <p>
     * Replace with synchronized hashmap lookup on obj.getClass()?
     **/
    private static int getItemType(Object obj) {
      if (obj instanceof PlanElement) {
        if (obj instanceof Allocation) {
          return ITEM_TYPE_ALLOCATION;
        } else if (obj instanceof Expansion) {
          return ITEM_TYPE_EXPANSION;
        } else if (obj instanceof Aggregation) {
          return ITEM_TYPE_AGGREGATION;
        } else if (obj instanceof Disposition) {
          return ITEM_TYPE_DISPOSITION;
        } else if (obj instanceof AssetTransfer) {
          return ITEM_TYPE_ASSET_TRANSFER;
        } else {
          return ITEM_TYPE_OTHER;
        }
      } else if (obj instanceof Task) {
        return ITEM_TYPE_TASK;
      } else if (obj instanceof Asset) {
        return ITEM_TYPE_ASSET;
      } else if (obj instanceof Workflow) {
        return ITEM_TYPE_WORKFLOW;
      } else {
        return ITEM_TYPE_OTHER;
      }
    }

    /**
     * SummaryInfo.
     * <p>
     * Counter holder
     **/
    private static class SummaryInfo {
      public int counter;
      public SummaryInfo() {
        counter = 0;
      }
      public static final Comparator LARGEST_COUNTER_FIRST_ORDER = 
        new Comparator() {
          public final int compare(Object o1, Object o2) {
            int c1 = ((SummaryInfo)o1).counter;
            int c2 = ((SummaryInfo)o2).counter;
            return ((c1 > c2) ? -1 : ((c1 == c2) ? 0 : 1));
          }
        };
    }

    /**
     * SummaryInfo.
     */
    private static class VerbSummaryInfo extends SummaryInfo {
      public Verb verb;
      public VerbSummaryInfo(Verb vb) {
        super();
        verb = vb;
      }
    }

    /**
     * Dates are formatted to "month_day_year_hour:minute[AM|PM]"
     */
    private static SimpleDateFormat myDateFormat;
    private static Date myDateInstance;
    private static java.text.FieldPosition myFieldPos;
    static {
      myDateFormat = new SimpleDateFormat("MM_dd_yyyy_h:mma");
      myDateInstance = new Date();
      myFieldPos = new java.text.FieldPosition(SimpleDateFormat.YEAR_FIELD);
    }

    /**
     * getTimeString.
     * <p>
     * Formats time to String.
     */
    private static String getTimeString(long time) {
      synchronized (myDateFormat) {
        myDateInstance.setTime(time);
        return 
          myDateFormat.format(
              myDateInstance,
              new StringBuffer(20), 
              myFieldPos
                             ).toString();
      }
    }

    /**
     * bit[] based upon URLEncoder.
     */
    static boolean[] DONT_NEED_ENCODING;
    static {
      DONT_NEED_ENCODING = new boolean[256];
      for (int i = 'a'; i <= 'z'; i++) {
        DONT_NEED_ENCODING[i] = true;
      }
      for (int i = 'A'; i <= 'Z'; i++) {
        DONT_NEED_ENCODING[i] = true;
      }
      for (int i = '0'; i <= '9'; i++) {
        DONT_NEED_ENCODING[i] = true;
      }
      DONT_NEED_ENCODING['-'] = true;
      DONT_NEED_ENCODING['_'] = true;
      DONT_NEED_ENCODING['.'] = true;
      DONT_NEED_ENCODING['*'] = true;

      // special-case to not encode "/"
      DONT_NEED_ENCODING['/'] = true;
    }

    /**
     * Saves some String allocations.
     */
    private static String encodeUID(String s) {
      int n = s.length();
      for (int i = 0; i < n; i++) {
        int c = (int)s.charAt(i);
        if (!(DONT_NEED_ENCODING[i])) {
          try {
            return URLEncoder.encode(s, "UTF-8");
          } catch (Exception e) {
            throw new IllegalArgumentException(
                "Unable to encode URL ("+s+")");
          }
        }
      }
      return s;
    }

    /**
     * XMLtoHTMLOutputStream.
     * <p>
     * Filter which converts XML to simple HTML.
     * Assumes &lt;pre&gt; tag surrounds this call, e.g.
     * <pre><code>
     *   String xml = "&gt;tag&lt;value&gt;/tag&lt;";
     *   PrintStream out = System.out;
     *   XMLtoHTMLOutputStream xout = new XMLtoHTMLOutputStream(out);
     *   out.print("&lt;pre&gt;\n");
     *   xout.print(xml);
     *   xout.flush();
     *   out.print("\n&lt;/pre&gt;");
     * </code></pre>
     * This keeps the spacing uniform and saves some writing.
     */
    public static class XMLtoHTMLOutputStream extends FilterWriter 
    {
      private static final char[] LESS_THAN;
      private static final char[] GREATER_THAN;
      static {
        LESS_THAN = "<font color=green>&lt;".toCharArray();
        GREATER_THAN = "&gt;</font>".toCharArray();
      }

      public XMLtoHTMLOutputStream(Writer w) {
        super(w);
      }

      public void write(String str, int off, int len) throws IOException 
      {
        int n = off+len;
        for (int i = off; i < n; i++) {
          write(str.charAt(i));
        }
      }

      public void write(char cbuf[], int off, int len) throws IOException 
      {
        int n = off+len;
        for (int i = off; i < n; i++) {
          write(cbuf[i]);
        }
      }

      public void write(int c) throws IOException {
        //
        // NOTE: "this.out" is *not* the PlanViewer's "out"!
        //
        if (c == '<') {
          this.out.write(LESS_THAN);
        } else if (c == '>') {
          this.out.write(GREATER_THAN);
        } else {
          this.out.write(c);
        }
      }
    }

 private static class UnaryPredicateParser {
   private static String CLNAME =
     "org.cougaar.lib.contract.lang.OperatorFactoryImpl";
   private static Integer STYLE =
     new Integer(13); //paren-pretty-verbose

   private static Exception loadE;
   private static Object inst;
   private static Method meth;

   public static UnaryPredicate parse(
       String s) throws Exception {
     ensureIsLoaded();
     return (UnaryPredicate)
       meth.invoke(inst, new Object[] {STYLE, s});
   }

   private static synchronized void ensureIsLoaded() throws Exception {
     if (inst == null) {
       if (loadE == null) {
         try {
           Class cl = Class.forName(CLNAME);
           meth = cl.getMethod(
               "create",
               new Class[] {Integer.TYPE, Object.class});
           inst = cl.newInstance();
           return;
         } catch (Exception e) {
           loadE = new RuntimeException(
               "Unable to load "+CLNAME, e);
         }
       }
       throw loadE;
     }
   }
 }

 /** END MISC UTILITIES **/
    /** END MISC UTILITIES **/
  }
}
