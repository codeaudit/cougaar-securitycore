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
