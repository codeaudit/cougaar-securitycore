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

package org.cougaar.core.security.dataprotection.plugin;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.certauthority.SecurityServletSupport;
import org.cougaar.core.security.dataprotection.DataProtectionKeyUnlockRequest;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.LoggingService;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeyRecoveryServlet
  extends  HttpServlet
{
  private SecurityServletSupport _support;
  private LoggingService _log;
  private KeyRecoveryRequestHandler _requestHandler;
  private MessageAddress _agentAddress;

  public KeyRecoveryServlet(SecurityServletSupport support) {
    _support = support;
    _log = (LoggingService)
      _support.getServiceBroker().getService(this,
					    LoggingService.class, null);
    AgentIdentificationService ais  = (AgentIdentificationService)
      _support.getServiceBroker().getService(this, AgentIdentificationService.class, null);
    _agentAddress = ais.getMessageAddress();

  }

  public void init(ServletConfig config)
    throws ServletException
  {
    _requestHandler = new KeyRecoveryRequestHandler(_support.getServiceBroker(), _agentAddress);
  }

  public void doPost (HttpServletRequest req, HttpServletResponse res)
    throws ServletException,IOException
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Processing key recovery request");
    }
    res.setContentType("text/html");

    try {
      ObjectInputStream ois = new ObjectInputStream(req.getInputStream());
      DataProtectionKeyUnlockRequest keyRequest =
	(DataProtectionKeyUnlockRequest)ois.readObject();
      _requestHandler.processKeyRecoveryRequest(keyRequest);

      ObjectOutputStream oos = new ObjectOutputStream(res.getOutputStream());
      oos.writeObject(keyRequest);
    }
    catch (Exception e) {
      if (_log.isWarnEnabled()) {
	_log.warn("Unable to process key recovery request", e);
      }
    }
  }

  protected void doGet(HttpServletRequest req,HttpServletResponse res)
    throws ServletException, IOException  {

  }

  public String getServletInfo()  {
    return("Process a key recovery request for the data protection service");
  }

}
