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
