/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 * 
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package org.cougaar.core.security.test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

// Cougaar core services
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.util.ConfigFinder;

public class TestSecureConfigFinder
  extends ComponentPlugin
{
  private LoggingService _log;
  private ConfigFinder _configFinder;

  protected void setupSubscriptions() {
    _log = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    _configFinder = getConfigFinder();

    readFiles();
  }

  protected void execute() {
  }

  private static final String _absoluteNodeConf = "/tmp/nodeConf.xml";

  private void readFiles() {
    InputStream is = null;
    File tmpFile = new File(_absoluteNodeConf);
    if (tmpFile.exists()) {
      tmpFile.delete();
    }

    // Try to read a file with an absolute path
    try {
      is = _configFinder.open(_absoluteNodeConf);
    }
    catch (IOException e) {
      _log.warn("Error while trying to access file" , e);
    }

    // The file should not exist
    if (is != null) {
      _log.error("File should not exist" , new Throwable());
    }
    else {
      _log.info("Test passed");
    }

    // Second test.
    try {
      tmpFile.createNewFile();
    }
    catch (IOException e) {
      _log.warn("Error while processing file" , e);
    }
    // Try to read a file with an absolute path
    try {
       is = _configFinder.open(_absoluteNodeConf);
    }
    catch (IOException e) {
      _log.warn("Error while trying to access file" , e);
    }
    // The file should exist
    if (is != null) {
      _log.info("Test passed");
    }
    else {
      _log.error("File should be found" , new Throwable());
    }
  }
}
