/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


/*
 * Created on Jun 4, 2003
 *
 *
 */
package org.cougaar.core.security.test.blackboard;


import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.glm.ldm.oplan.OrgActivity;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.PrepositionalPhrase;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.util.DBConnectionPool;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.DetectTime;


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
            logging.debug("Dumping test results to database");
        }

        dumpSQLResults();
    
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


    /**
     * Dump sql results
     */
    private void dumpSQLResults() {
        Connection connection = null;
        Statement stmt = null;
        try {
            //register driver
            if (logging.isDebugEnabled()) {
                logging.debug("Database details:" + driver + "," + databaseUrl
                    + "," + username + "," + password);
            }

            DBConnectionPool.registerDriver(driver);
            connection = DBConnectionPool.getConnection(databaseUrl, username,
                    password);
            stmt = connection.createStatement();
            String sql =
                "Insert into results (endtime,success,failure,total,plugin,agent,starttime,experimentName) values ("
                + "'" + new Date().toString() + "'" + "," + successes + ","
                + failures + "," + totalRuns + ",'" + pluginName + "'" + ",'"
                + getAgentIdentifier() + "'" + ",'" + startTime.toString()
                + "','" + expName + "')";
            if (logging.isInfoEnabled()) {
                logging.info(sql);
            }

            stmt.execute(sql);
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
    }


   


    /**
     * Load Component
     */
    public void load() {
        super.load();
        startTime = new Date();
        Collection parameters = getParameters();
        Iterator iter = parameters.iterator();
        while (iter.hasNext()) {
            try {
                String paramString = (String) iter.next();
                String param = paramString.substring(0, paramString.indexOf("="));
                String value = paramString.substring(paramString.indexOf("=")
                        + 1, paramString.length());
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
                    logging.error(
                        "*****************************Invalid format of plugin parameter should be PARAM=VALUE");

                }

                this.timeInterval = this.DEFAULT_TIME_INTERVAL;
            }
        }

        initAnalyzerDatabase();
        if (logging.isInfoEnabled()) {
            logging.info("*****************************Query time period:"
                + this.timeInterval);
        }
    }


    /**
     * Initialize Analyzer Database for this run
     */
    private void initAnalyzerDatabase() {
    }


    /**
     * Setup Plugin Subscriptions
     */
    public void setupSubscriptions() {
        this.operatingModeSubscription = (IncrementalSubscription) getBlackboardService()
                                                                       .subscribe(operatingModePredicate);
        this.testingSubscription = (IncrementalSubscription) getBlackboardService()
                                                                 .subscribe(testingPredicate);

        if (logging.isInfoEnabled()) {
            logging.info(
                "*****************************Done setting up subscriptions for "
                + pluginName);
        }
    }


    /**
     * Process subscriptions
     */
    public void execute() {
        if (logging.isInfoEnabled()) {
            logging.info("*****************************" + pluginName
                + " executing");
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


                PlanningFactory pf = (PlanningFactory) domainService.getFactory(
                        "planning");
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
     * @param a DOCUMENT ME!
     */
    protected void createIDMEFEvent(Analyzer a) {
        DetectTime detectTime = new DetectTime();
        detectTime.setIdmefDate(new java.util.Date());
        CmrFactory cmrFactory = (CmrFactory) this.domainService.getFactory(
                "cmr");
        Alert alert = cmrFactory.getIdmefMessageFactory().createAlert(a,
                detectTime, null, null, null, null);
        if (logging.isInfoEnabled()) {
            logging.info("*****************************Publishing IDMEF Event");
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
        Enumeration changedOperatingMode = operatingModeSubscription
            .getChangedList();
        if (changedOperatingMode.hasMoreElements()) {
            OperatingMode mode = (OperatingMode) changedOperatingMode
                .nextElement();
            Comparable value = mode.getValue();
            System.err.println(value.toString());
            this.timeInterval = (new Long(value.toString())).longValue();

        } else {
            changedOperatingMode = operatingModeSubscription.getAddedList();
            if (changedOperatingMode.hasMoreElements()) {
                OperatingMode mode = (OperatingMode) changedOperatingMode
                    .nextElement();
                Comparable value = mode.getValue();
                System.err.println(value.toString());
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
                logging.info(
                    "*****************************************TIMER TASK");
            }

            getBlackboardService().openTransaction();
            getBlackboardService().signalClientActivity();
            getBlackboardService().closeTransaction();
        }
    }
}
