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
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * XMLFormatter that overrides the format method to  output in the format
 * identified in the ServiceAudit.DTD
 *
 * @author ttschampel
 */
public class ServiceAuditXMLFormatter extends XMLFormatter {
  private static Logger log;
  static {
    log = LoggerFactory.getInstance().createLogger(ServiceAuditXMLFormatter.class);
  }
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
            if (log.isDebugEnabled()) {
              log.debug("We hit problems finding a canonical name.");
            }
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
            + "</agent>" + "\n" + "<resource>" + service + "</resource>" + "\n"
            + "<client>" + client + "</client>" + "\n</record>";

        return formattedString;
    }
}
