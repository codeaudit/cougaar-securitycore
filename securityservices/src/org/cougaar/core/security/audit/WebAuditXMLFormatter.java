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
            messageBuffer = messageBuffer.append("<authentication-type>"
                + token + "</authentication-type>");
            break;
          case 2:
            messageBuffer = messageBuffer.append("<user>" + token + "</user>");
            break;
          case 3:
            messageBuffer.append("\n<roles>" + token + "</roles>");
            break;
          case 4:
            messageBuffer.append("\n<client-ip>" + token + "</client-ip>");
            break;
          case 5:
            messageBuffer.append("\n<web-resource-ip>" + token
              + "</web-resource-ip>");
            break;
          case 6:
            messageBuffer.append("\n<servlet>" + token + "</servlet>");
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
