/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
 
 
 
 
 
 



package org.cougaar.core.security.audit;


import java.nio.charset.Charset;
import java.util.StringTokenizer;
import java.util.logging.Handler;
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
     * Return the header string for a set of XML formatted records.
     *
     * @param h The target handler.
     *
     * @return header string
     */
    public String getHead(Handler h) {
        StringBuffer sb = new StringBuffer();
        sb.append("<?xml version=\"1.0\"");
        String encoding = h.getEncoding();
        if (encoding == null) {
            // Figure out the default encoding.
            encoding = sun.io.Converters.getDefaultEncodingName();
        }

        // Try to map the encoding name to a canonical name.
        try {
            Charset cs = Charset.forName(encoding);
            encoding = cs.name();
        } catch (Exception ex) {
            // We hit problems finding a canonical name.
            // Just use the raw encoding name.
        }

        sb.append(" encoding=\"");
        sb.append(encoding);
        sb.append("\"");
        sb.append(" standalone=\"no\"?>\n");
        // sb.append("<!DOCTYPE log SYSTEM \"logger.dtd\">\n");
        sb.append("<log>\n");
        return sb.toString();
    }


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
            messageBuffer.append("\n<record>\n<timestamp>" + record.getMillis()
                + "</timestamp>");
            StringTokenizer tk = new StringTokenizer(message, ";");
            for (int i = 0; (i <= 5) && tk.hasMoreTokens(); i++) {
                String token = tk.nextToken();
                switch (i) {
                    case 0:
                        messageBuffer.append("\n<agent>" + token + "</agent>");
                        break;
                    case 1:
                        messageBuffer = messageBuffer.append(
                                "\n<authentication-type>" + token
                                + "</authentication-type>");
                        break;
                    case 2:
                        messageBuffer = messageBuffer.append("\n<user>" + token
                                + "</user>");
                        break;
                    case 3:
                        messageBuffer.append("\n<client-ip>" + token
                            + "</client-ip>");
                        break;
                    case 4:
                        messageBuffer.append("\n<web-resource-ip>" + token
                            + "</web-resource-ip>");
                        break;
                    case 5:
                        messageBuffer.append("\n<servlet>" + token
                            + "</servlet>");
                        break;
                }
            }
            while (tk.hasMoreTokens()) {
                String token = tk.nextToken();
                messageBuffer.append("\n<role>" + token + "</role>");
            }

            messageBuffer.append("\n</record>");
            formattedString = messageBuffer.toString();
        }

        return formattedString;
    }
}
