/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
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

package org.cougaar.core.security.policy.enforcers.util;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.service.LoggingService;

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;


import java.io.IOException;
import java.util.Iterator;
import java.util.List;

/**
 * The purpose of this class is to facilitate the mapping between DAML
 * concepts and the UltraLog concepts.  For now I am using
 * configuration files but some of this will change later...
 */
public class OwlServletMapping 
{
  private boolean             _initialized = false;
  private RegexpStringMapping _uriMap;
  private ServiceBroker        _sb;
  private LoggingService       _log;

  public OwlServletMapping(ServiceBroker sb)
  {
    _sb = sb;
    _log = (LoggingService) _sb.getService(this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("Initializing DAML Servlet Mapper");
    }
  }


  public void initializeUri()
  {
    try {
      _log.debug("loading uri mappings...");
      _uriMap = new RegexpStringMapping(_sb, "OwlMapUri");
    } catch (Exception e) {
      _log.error("Exception reading DAML <-> uri configuration file", e);
    }
  }

  public String ulUriToKAoSUri(String uri)
  {
    try {
      return EntityInstancesConcepts.EntityInstancesOwlURL()
                         + _uriMap.functionalGet(uri);
    } catch (Exception e) {
      _log.warn("This is probably not good - " + 
                "some URI is malformed...", e);
      return null;
    }
  }
}
