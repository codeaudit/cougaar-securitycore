/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  All Rights Reserved
 * </copyright>
 */


/*
 * Created on Jul 16, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.cougaar.core.security.audit;


import java.util.StringTokenizer;
import java.util.logging.LogRecord;
import java.util.logging.XMLFormatter;


/**
 * XMLFormatter that overrides the format method to 
 *  output in the format identified in the ServiceAudit.DTD
 *
 * @author ttschampel
 */
public class ServiceAuditXMLFormatter extends XMLFormatter {
    /**
     * Formats LogRecord output for easy audit purposes.
     *
     * @param record The LogRecord to format.  The message attribute of the
     *        LogRecord should be in the format Agent;Service;Client
     *
     * @return formatted XML String
     */
    public String format(LogRecord record) {
        String message = record.getMessage();
        String service = null;
        String client = null;
        String agent = null;
        if (message != null) {
            StringTokenizer st = new StringTokenizer(message, ";");
            int i = 0;
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                switch (i) {
                    case 0:
                        service = token;
                        break;
                    case 1:
                        service = token;
                        break;
                    case 2:
                        client = token;
                        break;
                }

                i++;
            }
        }

        String formattedString = "\n<record>" + "\n" + "<timestamp>"
            + record.getMillis() + "</timestamp>" + "\n" + "<agent>" + agent
            + "</agent>" + "\n" + "<resource>" + service + "</resource>"
            + "\n" + "<client>" + client + "</client>" + "\n</record>";

        return formattedString;
    }
}
