package org.cougaar.core.security.test;

import org.cougaar.core.plugin.SimplePlugin; 
import java.util.TimerTask; 
import java.util.Timer; 
import org.cougaar.core.agent.ClusterServesPlugin; 

public class ClockTimer extends SimplePlugin 
{ 
     ClusterServesPlugin cluster = null; 

     public ClockTimer() { 
        setThreadingChoice(SINGLE_THREAD); 
     } 

     // "initialization" method 
     public void setupSubscriptions() { 
        cluster = getCluster(); 

        startAdvancer(); 
        // don't actually set up any subscriptions 
     } 

     public void execute() { 
     } 



     private void startAdvancer() { 
        TimerTask t = new Advancer(); 
        Timer timer = new Timer(); 
        // Advance time every 10 seconds, starting at 20 seconds 
        timer.schedule(t, 20000, 10000); 
     } 

     private class Advancer extends TimerTask { 
        public void run() { 
            // Note - we can do this directly (without a transaction) 
            // because time is not LDM controlled. 
            System.err.println(" Advancing to "+ 
                               new java.util.Date(cluster.currentTimeMillis()+10*60*1000) 
                               ); 
            cluster.advanceTime(10 * 60 * 1000); 

            // if we were using this loop to *activate* the plugin 
            // every 10 (realtime) seconds, we'd do something like: 
            // plugin.wake(); 
        } 
     } 
} 

