/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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

package org.cougaar.core.security.monitoring.servlet;

// Imported TraX classes
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerConfigurationException;


// Imported java classes
import java.io.*;
import java.util.Collection;
import java.util.Iterator;
import javax.servlet.*;
import javax.servlet.http.*;

// IDMEF
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Alert;

// Cougaar core services
import org.cougaar.core.servlet.SimpleServletSupport;
import org.cougaar.util.*;

// Cougaar security services
import org.cougaar.core.security.provider.SecurityServiceProvider;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.security.monitoring.blackboard.*;
import org.cougaar.core.security.monitoring.idmef.*;

/**
 *  Use the TraX interface to perform a transformation.
 */
public class EventViewerServlet
  extends HttpServlet
{
  private SimpleServletSupport support;
  private ConfigFinder confFinder;
  private SecurityPropertiesService secprop;
  private StreamSource stylesheet;
  private Transformer transformer;

   /** Creates new predicate to search for Events */
  class IdmefEventPredicate implements UnaryPredicate
  {
    /** @return true if the object "passes" the predicate */
    public boolean execute(Object o) {
      if (o instanceof Event)  {
	Event event= (Event)o;
	IDMEF_Message msg = event.getEvent();
	return true;
      }
      return false;
    }
  }

  public EventViewerServlet(SimpleServletSupport support) {
    this.support = support;

    confFinder = new ConfigFinder();
    // TODO. Modify following line to use service broker instead
    secprop = SecurityServiceProvider.getSecurityProperties(null);
  }

  public void init(ServletConfig config)
    throws ServletException {
 
    File f = null;
    String stylesheetFile = "idmef-message.html.xsl";
    f = confFinder.locateFile(stylesheetFile);

    stylesheet = new StreamSource(f);

    try {
      // Use the static TransformerFactory.newInstance() method to instantiate 
      // a TransformerFactory. The javax.xml.transform.TransformerFactory 
      // system property setting determines the actual class to instantiate --
      // org.apache.xalan.transformer.TransformerImpl.
      TransformerFactory tFactory = TransformerFactory.newInstance();
    
      // Use the TransformerFactory to instantiate a Transformer that will work with  
      // the stylesheet you specify. This method call also processes the stylesheet
      // into a compiled Templates object.
      transformer = tFactory.newTransformer(stylesheet);
    }
    catch (TransformerConfigurationException e) {
      System.out.println("Unable to initialize XSL stylesheet");
    }
  }

  public void doGet(HttpServletRequest request,
		    HttpServletResponse response)
    throws IOException {
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();

    // Query the blackboard
    Collection collection = support.queryBlackboard(new IdmefEventPredicate());
    Iterator it = collection.iterator();
    String document = null;
    StreamSource inputXML = null;
    if (!it.hasNext()) {
      out.print("No Event available");
    }
    while (it.hasNext()) {
      IDMEF_Message msg = ((Event)it.next()).getEvent();
      document = msg.toString();
      System.out.println("IDMEF message:\n" + document);
      inputXML = new StreamSource(new StringReader(document));
      doTransform(out, inputXML);
    }
    out.flush();
    out.close();
  }

  private void doTransform(PrintWriter writer, StreamSource inputXML) {
    try {
      // Use the Transformer to apply the associated Templates object to an XML document
      transformer.transform(inputXML, new StreamResult(writer));
    }
    catch (TransformerException e) {
      writer.print("Unable to get IDMEF events");
      e.printStackTrace(writer);
    }
  }
}
