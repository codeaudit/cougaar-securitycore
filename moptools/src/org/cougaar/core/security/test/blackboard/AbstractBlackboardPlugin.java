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
 * Created on Jun 4, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;

import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.PrepositionalPhrase;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.UnaryPredicate;

import java.io.File;
import java.io.FileWriter;
import java.io.Serializable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;


/**
 * DOCUMENT ME!
 *
 * @author ttschampel
 */
public abstract class AbstractBlackboardPlugin extends ComponentPlugin {
  /** Plugin parameter for time interval */
  protected static final String TIME_INTERVAL_PLUGIN_PARAM = "TIMERINTERVAL";
  /** Plugin parameter for analyzer database */
  protected static final String ANALYZER_DATABASE_PLUGIN_PARAM = "DATABASEURL";
  /** Plugin parameter for driver to datbase */
  protected static final String ANALYZER_DRIVER_PLUGIN_PARAM = "DRIVER";
  /** Plugin parameter for database username */
  protected static final String ANALYZER_USERNAME_PLUGIN_PARAM = "USERNAME";
  /** Plugin parameter for database password */
  protected static final String ANALYZER_PASSWORD_PLUGIN_PARAM = "PASSWORD";
  protected static final String ANALYZER_DUMP_DIR_PLUGIN_PARAM = "DUMP_DIR";
  /** Plugin name */
  protected String pluginName;
  private String databaseUrl;
  private String username;
  private String password;
  private String driver;
  protected int totalRuns;
  private String dumpDir;
  protected int successes;
  protected int failures;
  protected Date startTime;
  protected Date endTime;
  protected String expName;
  private boolean stopTesting = false;
  /** Logging Service */
  protected LoggingService logging;
  /** DomainService */
  protected DomainService domainService;
  /** Subscription to operating mode */
  protected IncrementalSubscription operatingModeSubscription;
  /** Subscription to blackboard test tasks */
  protected IncrementalSubscription testingSubscription;
  protected UnaryPredicate testingPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof Task) {
        Task t = (Task) o;
        return t.getVerb().toString().equals(BlackboardTestManagerServlet.VERB);

      }

      return false;
    }
  };

  /** Predicate for operating mode */
  protected UnaryPredicate operatingModePredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof OperatingMode) {
        OperatingMode m = (OperatingMode) o;
        if (m.getName() != null) {
          return m.getName().equals(BlackboardOMTestPlugin.BLACKBOARD_TEST_OM);
        }
      }

      return false;

    }
  };

  /** Predicate for OrgActivity objects */
  protected UnaryPredicate orgActivityPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      return o instanceof OrgActivity;
    }
  };

  /** Time interval between blackboard queries for org activity */
  protected long timeInterval = 0;
  /** Default polling interval for org activities */
  protected final long DEFAULT_TIME_INTERVAL = 10000;

  /**
   * DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  protected PlanningFactory getPlanningFactory() {
    return (PlanningFactory) domainService.getFactory("planning");
  }


  /**
   * Setup logging service
   *
   * @param logging
   */
  public void setLoggingService(LoggingService logging) {
    this.logging = logging;
  }


  /**
   * Set DomainService
   *
   * @param service
   */
  public void setDomainService(DomainService service) {
    this.domainService = service;
  }


  /**
   * dumps test results to database
   */
  public void dumpResults() {
    if (logging.isDebugEnabled()) {
      logging.debug("Dumping test results to database for " + pluginName);
    }

    dumpCSVResults();
    dumpHTMLResults();

  }


  /**
   * Unload component, if stop testing has not been called then dump data
   */
  public void unload() {
    super.unload();
    if (!this.stopTesting) {
      this.endTime = new Date();
      this.dumpResults();
    }
  }


  private void dumpCSVResults() {
    String filename = dumpDir + File.separator + expName + "-" + getAgentIdentifier().toAddress() + "-" + pluginName + ".csv";
    try {
      File file = new File(filename);
      FileWriter writer = new FileWriter(file);
      writer.write("Experiment Name, Start Time, End Time, Successes, Failures, Total Tries, Agent Name, Plugin name");

      writer.write("\n");
      writer.write(expName + "," + startTime.toString() + "," + endTime.toString() + "," + successes + "," + failures + "," + totalRuns + "," + this.getAgentIdentifier().getAddress() + "," + pluginName);


      writer.close();


    } catch (Exception e) {
      if (logging.isErrorEnabled()) {
        logging.error("error dumping test results to csv file: " + filename, e);

      }
    }
  }


  private void dumpHTMLResults() {
    try {
      String filename = dumpDir + File.separator + expName + "-" + getAgentIdentifier().toAddress() + "-" + pluginName + ".html";
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
      writer.write("<TR>");
      writer.write("<TD>" + expName + "</TD>");
      writer.write("<TD>" + startTime + "</TD>");
      writer.write("<TD>" + endTime + "</TD>");
      writer.write("<TD>" + successes + "</TD>");
      writer.write("<TD>" + failures + "</TD>");
      writer.write("<TD>" + totalRuns + "</TD>");
      writer.write("<TD>" + this.getAgentIdentifier().getAddress() + "</TD>");
      writer.write("<TD>" + pluginName + "</TD>");

      writer.write("</TR>");

      writer.write("</TABLE></BODY></HTML>");
      writer.close();
    } catch (Exception e) {
      if (logging.isErrorEnabled()) {
        logging.error("Error writing html results", e);
      }
    }
  }


  /**
   * Load Component
   */
  public void load() {
    super.load();
    startTime = new Date();
    Collection parameters = getParameters();
    Iterator iter = parameters.iterator();

    dumpDir = System.getProperty("org.cougaar.workspace") + File.separator + "security" + File.separator + "mopresults";

    while (iter.hasNext()) {
      try {
        String paramString = (String) iter.next();
        String param = paramString.substring(0, paramString.indexOf("="));
        String value = paramString.substring(paramString.indexOf("=") + 1, paramString.length());
        if (param.equals(TIME_INTERVAL_PLUGIN_PARAM)) {
          this.timeInterval = Long.parseLong(value);
        } else if (param.equals(ANALYZER_DATABASE_PLUGIN_PARAM)) {
          this.databaseUrl = value;
        } else if (param.equals(ANALYZER_DRIVER_PLUGIN_PARAM)) {
          this.driver = value;
        } else if (param.equals(ANALYZER_PASSWORD_PLUGIN_PARAM)) {
          this.password = value;
        } else if (param.equals(ANALYZER_USERNAME_PLUGIN_PARAM)) {
          this.username = value;
        } else if (param.equals(ANALYZER_DUMP_DIR_PLUGIN_PARAM)) {
          this.dumpDir = value;
        }
      } catch (Exception nfe) {
        if (logging.isErrorEnabled()) {
          logging.error("Invalid format of plugin parameter should be PARAM=VALUE");

        }

        this.timeInterval = this.DEFAULT_TIME_INTERVAL;
      }
    }

    initAnalyzerDatabase();
    if (logging.isInfoEnabled()) {
      logging.info("Query time period:" + this.timeInterval);
    }
  }


  /**
   * Initialize Analyzer Database for this run
   */
  private void initAnalyzerDatabase() {
    try {
      if (logging.isInfoEnabled()) {
        logging.info("Dump directory:" + dumpDir);
      }

      File dumpDirFile = new File(dumpDir);
      if (!dumpDirFile.mkdirs()) {
        if (logging.isInfoEnabled()) {
          logging.info("Unable to create dump directory:" + dumpDir);
        }
      }
    } catch (Exception e) {
      if (logging.isWarnEnabled()) {
        logging.warn("Unable to create dump directory:" + e);
      }
    }
  }


  /**
   * Setup Plugin Subscriptions
   */
  public void setupSubscriptions() {
    this.operatingModeSubscription = (IncrementalSubscription) getBlackboardService().subscribe(operatingModePredicate);
    this.testingSubscription = (IncrementalSubscription) getBlackboardService().subscribe(testingPredicate);

    if (logging.isInfoEnabled()) {
      logging.info("Done setting up subscriptions for " + pluginName);
    }
  }


  /**
   * Process subscriptions
   */
  public void execute() {
    if (logging.isInfoEnabled()) {
      logging.info(pluginName + " executing");
    }

    processOperatingMode();
    processTesting();
    if (this.wasAwakened()) {
      queryBlackboard();
      if (this.stopTesting) {
        this.endTime = new Date();
        dumpResults();
      } else {
        Timer timer = new Timer();
        QueryTimerTask qtt = new QueryTimerTask();
        timer.schedule(qtt, timeInterval);

      }
    }
  }


  private void processTesting() {
    Enumeration enum = testingSubscription.getAddedList();
    if (enum.hasMoreElements()) {
      Task task = (Task) enum.nextElement();
      PrepositionalPhrase p = task.getPrepositionalPhrase(BlackboardTestManagerServlet.STATUS);
      String status = (String) p.getIndirectObject();
      PrepositionalPhrase expP = task.getPrepositionalPhrase(BlackboardTestManagerServlet.EXP_NAME_PREP);
      this.expName = (String) expP.getIndirectObject();
      if (status.equals(BlackboardTestManagerServlet.START_TESTING)) {
        this.stopTesting = false;
        Timer timer = new Timer();
        QueryTimerTask timerTask = new QueryTimerTask();
        timer.schedule(timerTask, this.timeInterval);


        PlanningFactory pf = (PlanningFactory) domainService.getFactory("planning");
        NewTask newtask = pf.newTask();
        newtask.setVerb(Verb.getVerb(AnalyzerServlet.VERB));
        Vector phrases = new Vector();
        NewPrepositionalPhrase npp1 = pf.newPrepositionalPhrase();
        npp1.setIndirectObject(this.username);
        npp1.setPreposition(AnalyzerServlet.DB_USERNAME);
        phrases.add(npp1);

        NewPrepositionalPhrase npp2 = pf.newPrepositionalPhrase();
        npp2.setIndirectObject(this.password);
        npp2.setPreposition(AnalyzerServlet.DB_PASSWORD);
        phrases.add(npp2);

        NewPrepositionalPhrase npp3 = pf.newPrepositionalPhrase();
        npp3.setIndirectObject(this.driver);
        npp3.setPreposition(AnalyzerServlet.DB_DRIVER);
        phrases.add(npp3);

        NewPrepositionalPhrase npp4 = pf.newPrepositionalPhrase();
        npp4.setIndirectObject(this.databaseUrl);
        npp4.setPreposition(AnalyzerServlet.DB_URL);
        phrases.add(npp4);
        NewPrepositionalPhrase npp5 = pf.newPrepositionalPhrase();
        npp5.setIndirectObject(this.dumpDir);
        npp5.setPreposition(AnalyzerServlet.DUMP_DIR);
        phrases.add(npp5);
        NewPrepositionalPhrase npp6 = pf.newPrepositionalPhrase();
        npp6.setIndirectObject(this.expName);
        npp6.setPreposition(AnalyzerServlet.EXP_NAME);
        phrases.add(npp6);
        newtask.setPrepositionalPhrases(phrases.elements());
        getBlackboardService().publishAdd(newtask);

      } else if (status.equals(BlackboardTestManagerServlet.END_TESTING)) {
        this.stopTesting = true;
        this.endTime = new Date();
        this.dumpResults();
      }
    }
  }


  /**
   * Query blackboard
   */
  protected abstract void queryBlackboard();


  /**
   * DOCUMENT ME!
   *
   * @param str DOCUMENT ME!
   */
  protected void setPluginName(String str) {
    this.pluginName = str;
  }


  /**
   * Create IDMEF Event
   *
   * @param sensorName DOCUMENT ME!
   * @param classification DOCUMENT ME!
   */
  protected void createIDMEFEvent(final String sensorName, String classification) {
    DetectTime detectTime = new DetectTime();
    detectTime.setIdmefDate(new java.util.Date());
    CmrFactory cmrFactory = (CmrFactory) this.domainService.getFactory("cmr");
    ArrayList classifications = new ArrayList();
    Classification c = (Classification) cmrFactory.getIdmefMessageFactory().createClassification(classification, null);
    classifications.add(c);
    Analyzer a = cmrFactory.getIdmefMessageFactory().createAnalyzer(new SensorInfo() {
        public String getName() {
          return sensorName;
        }


        public String getManufacturer() {
          return "CSI";
        }


        public String getModel() {
          return "BlackboardTool";
        }


        public String getVersion() {
          return "1.0";
        }


        public String getAnalyzerClass() {
          return "BlackboardAccessControlPlugin";
        }
      });

    Alert alert = cmrFactory.getIdmefMessageFactory().createAlert(a, detectTime, null, null, classifications, null);
    if (logging.isInfoEnabled()) {
      logging.info("Publishing IDMEF Event");
    }

    Event event = cmrFactory.newEvent(alert);

    if (!(event instanceof Serializable)) {
      if (logging.isErrorEnabled()) {
        logging.error("Event is not serializable");
      }
    }

    getBlackboardService().publishAdd(event);

  }


  /**
   * Look for any new or changed operating modes we are interested in
   */
  protected void processOperatingMode() {
    Enumeration changedOperatingMode = operatingModeSubscription.getChangedList();
    if (changedOperatingMode.hasMoreElements()) {
      OperatingMode mode = (OperatingMode) changedOperatingMode.nextElement();
      Comparable value = mode.getValue();

      //System.err.println(value.toString());
      this.timeInterval = (new Long(value.toString())).longValue();

    } else {
      changedOperatingMode = operatingModeSubscription.getAddedList();
      if (changedOperatingMode.hasMoreElements()) {
        OperatingMode mode = (OperatingMode) changedOperatingMode.nextElement();
        Comparable value = mode.getValue();

        //System.err.println(value.toString());
        this.timeInterval = (new Long(value.toString())).longValue();
      }
    }
  }

  /**
   * Timer Task that uses the BlackboardService.signalClientActivity()
   */
  protected class QueryTimerTask extends TimerTask {
    public QueryTimerTask() {
      super();
    }

    public void run() {
      if (logging.isInfoEnabled()) {
        logging.info("*****************************************TIMER TASK");
      }

      getBlackboardService().openTransaction();
      getBlackboardService().signalClientActivity();
      getBlackboardService().closeTransaction();
    }
  }
}
