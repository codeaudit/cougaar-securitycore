/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


package org.cougaar.core.security.test.blackboard;


import com.cougaarsoftware.common.servlet.AdvancedSimpleServletComponent;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.util.UnaryPredicate;

import java.io.IOException;
import java.io.PrintWriter;

import java.lang.reflect.Constructor;

import java.util.Collection;
import java.util.Iterator;


/**
 * Servlet to access and change the Blacboard test plugins operating mode
 *
 * @author mabrams
 */
public class AEChangeModeServlet extends AdvancedSimpleServletComponent {
	/** operating mode change parameter */
    private static final String CHANGE = "change";
    /** operating mode name parameter */
    private static final String NAME = "name";
	/** operating mode value parameter */
    private static final String VALUE = "value";
	/** the name of this component */
    private final String pluginName = "AEChangeModeServlet";

    /**
     * Sets the path for the servlet
     *
     * @return the servlet path
     */
    protected String getPath() {       
        return "/aeChangeMode";
    }

    /**
     * Executed when the servlet is accessed        
     */
    protected void execute(HttpServletRequest request,
        HttpServletResponse response) {
        String change = request.getParameter(CHANGE);
        PrintWriter out = null;
        try {
            out = response.getWriter();
        } catch (IOException e) {
            e.printStackTrace();
        }
        boolean success = false;
        if (change != null) {
            blackboardService.openTransaction();
            success = changeOperatingMode(request, out);
            blackboardService.closeTransaction();
        } 
        
        if (!success) {
        	out.println("<h1>There was an error changing the operating mode, check the logs</h1>");        	
        }
    }


    private boolean changeOperatingMode(HttpServletRequest request, PrintWriter out) {
        // get the string representing the operating mode
        String omName = request.getParameter(NAME);
        if (omName == null) {
        	out.println("<br>No OperatingMode name provided in the servlet parameters");
            return false;
        }

                
        // find the existing operating mode on the blackboard
        Collection blackboardCollection = blackboardService.query(new OMByNamePredicate(
                    omName));

        Iterator i = blackboardCollection.iterator();
        OperatingMode bbOM = null;
        if (i.hasNext()) {
            bbOM = (OperatingMode) i.next();
        } else {
            out.println("Sorry:" + omName + " does not exist on the blackboard");
            return false;
        }

        String newValue = request.getParameter(VALUE);
        if (newValue == null) {
            return false;
        }
        
        Class omClass = null;
        if (bbOM != null) {
            omClass = bbOM.getValue().getClass();
        } else {
            out.println("<b>ERROR, BBOM was NULL</b>");
            return false;
        }

        // Is it a String?
        try {
            if (omClass == String.class) {
                // set it and be done with it.
                bbOM.setValue(newValue);
            } else {
                // If not, hope that whatever it is has a String constructor
                Constructor cons = null;
                try {
                    cons = omClass.getConstructor(new Class[] { String.class });
                } catch (NoSuchMethodException nsme) {
                    System.err.println(
                        "AEViewerServlet: Error, no String constructor for OperatingMode containing class "
                        + omClass + " " + nsme);
                    out.println(
                        "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
                    out.println(
                        "There is no String constructor for OperatingMode containing class "
                        + omClass + " " + nsme);
                    return false;
                } catch (RuntimeException re) {
                    out.println(
                        "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
                    out.println(re);
                    return false;
                }

                if (cons != null) {
                    // Make a new one of whatever it is and set OM value
                    Comparable newThing = (Comparable) cons.newInstance(new String[] {
                                newValue
                            });
                    bbOM.setValue(newThing);
                } else {
                    out.println(
                        "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
                    out.print("Can't set ");
                    out.print(bbOM.getName());
                    out.print("to " + newValue);
                    out.println("<br>No constructor " + omClass + "(String)");
                }
            }
        } catch (IllegalArgumentException iae) {
            out.println(
                "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
            out.print(newValue);
            out.print(" is not a valid value for ");
            out.println(bbOM.getName());
            out.print("<br>");
            out.println(iae);
            return false;
        } catch (java.lang.reflect.InvocationTargetException ite) {
            out.println(
                "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
            out.print(newValue);
            out.print(" is not a valid value for ");
            out.println(bbOM.getName());
            out.print("<br>");
            out.println(ite);
            return false;
        } catch (InstantiationException ie) {
            out.println(
                "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
            out.print(ie);
            return false;
        } catch (IllegalAccessException iae) {
            out.println(
                "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
            out.print(iae);
            return false;
        } catch (RuntimeException re) {
            out.println(
                "<html><head></head><body><h2>ERROR - OperatingMode Not Changed</h2><br>");
            out.print(re);
            return false;
        }

        // write the updated operating mode to the blackboard
        blackboardService.publishChange(bbOM);

        out.println(
            "<html><head></head><body><h2>OperatingMode Changed</h2><br>");
        out.println(bbOM.toString());
        return true;
    }

    private class OMByNamePredicate implements UnaryPredicate {
        String name;

        public OMByNamePredicate(String omName) {
            name = omName;
        }

        public boolean execute(Object o) {
            if (o instanceof OperatingMode) {
                OperatingMode om = (OperatingMode) o;
                if (name.equals(om.getName())) {
                    return true;
                }
            }

            return false;
        }
    }
}
