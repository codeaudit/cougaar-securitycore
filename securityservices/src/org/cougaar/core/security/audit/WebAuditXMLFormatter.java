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
 * An XMLFormatter that overrides the format method to ouput the results in the
 * format identified by the WebAudit.dtd
 *
 * @author ttschampel
 */
public class WebAuditXMLFormatter extends XMLFormatter {
    /**
     * Formates a LogRecord into a format specified by WebAudit.dtd
     *
     * @param record The LogRecord to Format
     *
     * @return The formatted XML String
     */
    public String format(LogRecord record) {
        String formattedString = null;
        String message = record.getMessage();
        StringBuffer messageBuffer = new StringBuffer();
        if (message != null) {
            messageBuffer.append("<record>\n<timestamp>" + record.getMillis()
                + "</timestamp>");
            StringTokenizer tk = new StringTokenizer(message, ";");
            int i = 0;
            while (tk.hasMoreTokens()) {
                String token = tk.nextToken();
                switch (i) {
                    case 0:
                        messageBuffer.append("\n<agent>" + token + "</agent>");
                        break;
                    case 1:
                        messageBuffer = messageBuffer.append(
                                "<authentication-type>" + token
                                + "</authentication-type>");
                        break;
                    case 2:
                        messageBuffer = messageBuffer.append("<user>" + token
                                + "</user>");
                        break;
                    case 3:
                        messageBuffer.append("\n<roles>" + token + "</roles>");
                        break;
                    case 4:
                        messageBuffer.append("\n<client-ip>" + token
                            + "</client-ip>");
                        break;
                    case 5:
                        messageBuffer.append("\n<web-resource-ip>" + token
                            + "</web-resource-ip>");
                        break;
                    case 6:
                        messageBuffer.append("\n<servlet>" + token
                            + "</servlet>");
                        break;
                }

                i++;
            }

            messageBuffer.append("\n</record>");
            formattedString = messageBuffer.toString();
        }

        return formattedString;
    }
}
