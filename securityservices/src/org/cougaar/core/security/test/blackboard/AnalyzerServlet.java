/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 *
 * </copyright>
 *
 * CHANGE RECORD
 * -
 */


/*
 * Created on Jun 6, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.util.DBConnectionPool;
import org.cougaar.util.UnaryPredicate;

import java.io.File;
import java.io.FileWriter;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;


/**
 * Servlet that creates csv and HTML format
 *
 * @author ttschampel
 */
public class AnalyzerServlet extends BaseServletComponent
  implements BlackboardClient {
  /** DOCUMENT ME! */
  public static final String DB_USERNAME = "username";
  /** DOCUMENT ME! */
  public static final String DB_PASSWORD = "password";
  /** DOCUMENT ME! */
  public static final String DB_DRIVER = "driver";
  /** DOCUMENT ME! */
  public static final String DB_URL = "url";
  /** DOCUMENT ME! */
  public static final String EXP_NAME = "expName";
  /** DOCUMENT ME! */
  public static final String DUMP_DIR = "dir";
  /** DOCUMENT ME! */
  public static final String VERB = "DB_TEST_DETAILS";
  /** Cougaar BlackboardService */
  protected BlackboardService blackboardService;
  /** Cougaar Logging Service */
  protected LoggingService logging;
  /** Cougaar DomainService */
  protected DomainService domainService;
  private UnaryPredicate thePredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Task) {
          Task t = (Task) o;
          return (t.getVerb() != null) && t.getVerb().toString().equals(VERB);
        }

        return false;

      }
    };

  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#getPath()
   */
  protected String getPath() {
    // TODO Auto-generated method stub
    return "/analyze";

  }


  /* (non-Javadoc)
   * @see com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent#execute(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
   */
  protected void execute(HttpServletRequest request,
    HttpServletResponse response) {
    boolean processResults = false;
    String username = null;
    String pwd = null;
    String driver = null;
    String dir = null;
    String url = null;
    String expName = null;
    blackboardService.openTransaction();
    Collection coll = blackboardService.query(thePredicate);
    Iterator iter = coll.iterator();
    if (iter.hasNext()) {
      Task task = (Task) iter.next();
      processResults = true;
      username = (String) task.getPrepositionalPhrase(DB_USERNAME)
                              .getIndirectObject();
      pwd = (String) task.getPrepositionalPhrase(DB_PASSWORD).getIndirectObject();
      driver = (String) task.getPrepositionalPhrase(DB_DRIVER)
                            .getIndirectObject();
      dir = (String) task.getPrepositionalPhrase(DUMP_DIR).getIndirectObject();
      url = (String) task.getPrepositionalPhrase(DB_URL).getIndirectObject();
      expName = (String) task.getPrepositionalPhrase(EXP_NAME)
                             .getIndirectObject();

    }

    blackboardService.closeTransaction();
    if (processResults) {
      ArrayList results = new ArrayList();
      Connection connection = null;
      Statement stmt = null;
      ResultSet rs = null;
      try {
        //register driver
        DBConnectionPool.registerDriver(driver);
        connection = DBConnectionPool.getConnection(url, username, pwd);
        stmt = connection.createStatement();
        String sql = "Select * from results where experimentName='" + expName
          + "' order by agent,plugin";
        rs = stmt.executeQuery(sql);
        while (rs.next()) {
          TestResult result = new TestResult();
          result.agentName = rs.getString("agent");
          result.endTime = rs.getString("endtime");
          result.expName = rs.getString("experimentName");
          result.failures = rs.getInt("failure");
          result.pluginName = rs.getString("plugin");
          result.startTime = rs.getString("starttime");
          result.totalRuns = rs.getInt("total");
          result.successes = rs.getInt("success");
          results.add(result);
        }

        if (logging.isInfoEnabled()) {
          logging.info(sql);
        }
      } catch (SQLException sqlex) {
        if (logging.isErrorEnabled()) {
          logging.error("Error writing test result to databse", sqlex);
        }
      } catch (Exception e) {
        if (logging.isErrorEnabled()) {
          logging.error("Error registering driver " + driver, e);
        }
      } finally {
        try {
          if (rs != null) {
            rs.close();
          }

          if (stmt != null) {
            stmt.close();
          }

          if (connection != null) {
            connection.close();
          }
        } catch (SQLException sqlex2) {
          if (logging.isErrorEnabled()) {
            logging.error("Error closing db resourcses," + sqlex2);
          }
        }
      }

      writeResults(results, expName, dir);
    }

    if (logging.isInfoEnabled()) {
      logging.info("Done executing ");
    }
  }


  private void writeResults(ArrayList results, String expName, String dir) {
    if (logging.isInfoEnabled()) {
      logging.info("writing results");
    }

    //write to CSV
    dumpCSVResults(results, expName, dir);
    //write to HTML
    dumpHTMLResults(results, expName, dir);
  }


  private void dumpCSVResults(ArrayList results, String expName, String dir) {
    try {
      String filename = dir + File.separator + expName + ".csv";
      File file = new File(filename);
      FileWriter writer = new FileWriter(file);
      writer.write(
        "Experiment Name, Start Time, End Time, Successes, Failures, Total Tries, Agent Name, Plugin name");
      for (int i = 0; i < results.size(); i++) {
        TestResult result = (TestResult) results.get(i);
        writer.write("\n");
        writer.write(result.expName + "," + result.startTime.toString() + ","
          + result.endTime.toString() + "," + result.successes + ","
          + result.failures + "," + result.totalRuns + "," + result.agentName
          + "," + result.pluginName);
      }

      writer.close();


    } catch (Exception e) {
      if (logging.isErrorEnabled()) {
        logging.error("error dumping test results to csv file", e);
      }
    }
  }


  private void dumpHTMLResults(ArrayList results, String expName, String dir) {
    try {
      String filename = dir + File.separator + expName + ".html";
      File file = new File(filename);
      FileWriter writer = new FileWriter(file);
      writer.write("<HTML><BODY><TABLE><TR>");
      writer.write("<TH>Experiment</TH>");
      writer.write("<TH>Start Time</TH>");
      writer.write("<TH>End Time</TH>");
      writer.write("<TH>Successes</TH>");
      writer.write("<TH>Failures</TH>");
      writer.write("<TH>Total</TH>");
      writer.write("<TH>Agent</TH>");
      writer.write("<TH>Plugin</TH>");
      writer.write("</TR>");
      for (int i = 0; i < results.size(); i++) {
        TestResult result = (TestResult) results.get(i);
        writer.write("<TR>");
        writer.write("<TD>" + result.expName + "</TD>");
        writer.write("<TD>" + result.startTime + "</TD>");
        writer.write("<TD>" + result.endTime + "</TD>");
        writer.write("<TD>" + result.successes + "</TD>");
        writer.write("<TD>" + result.failures + "</TD>");
        writer.write("<TD>" + result.totalRuns + "</TD>");
        writer.write("<TD>" + result.agentName + "</TD>");
        writer.write("<TD>" + result.pluginName + "</TD>");

        writer.write("</TR>");
      }

      writer.write("</TABLE></BODY></HTML>");
      writer.close();
    } catch (Exception e) {
      if (logging.isErrorEnabled()) {
        logging.error("Error writing html results", e);
      }
    }
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.servlet.BaseServletComponent#createServlet()
   */
  protected Servlet createServlet() {
    return new MyServlet();
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#getBlackboardClientName()
   */
  public String getBlackboardClientName() {
    // TODO Auto-generated method stub
    return null;
  }


  /* (non-Javadoc)
   * @see org.cougaar.core.blackboard.BlackboardClient#currentTimeMillis()
   */
  public long currentTimeMillis() {
    // TODO Auto-generated method stub
    return 0;
  }

  private class MyServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) {
      execute(request, response);
    }
  }


  private class TestResult {
    public String expName;
    public String startTime;
    public String endTime;
    public int successes;
    public int failures;
    public int totalRuns;
    public String agentName;
    public String pluginName;
  }
}
