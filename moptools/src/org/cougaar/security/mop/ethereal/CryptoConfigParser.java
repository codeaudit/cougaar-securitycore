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

package org.cougaar.security.mop.ethereal;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;

public class CryptoConfigParser
{
  private BufferedReader _reader;
  private Logger _log;
  private Map _protocolConfig = new HashMap();

  public CryptoConfigParser() {
    _log = LoggerFactory.getInstance().createLogger(this);
  }

  public Map getProtocolPolicy() {
    return _protocolConfig;
  }

  public void parseConfigFile(String filename) {
    if (filename == null) {
      filename = System.getProperty("org.cougaar.security.mop.protocolPolicy");
    }
    try {
      _reader = new BufferedReader(new FileReader(filename));
    }
    catch (IOException e) {
      _log.warn("Unable to read file:" + filename);
    }
    String line = null;

    Pattern pattern = Pattern.
      compile("(\\S*)(\\s*)(\\S*)(\\s*)(\\S*)");
    Matcher matcher = null;

    try {
      while ( (line = _reader.readLine()) != null ) {
	if (line.startsWith("#")) {
	  continue;
	}
	matcher = pattern.matcher(line);
	boolean match = matcher.find();
	if (!match) {
	  if (_log.isWarnEnabled()) {
	    _log.warn("Unable to find expected pattern at line: " + line);
	  }
	  continue; // Line does not match pattern
	}

	String protocolName = matcher.group(1);
	String value = matcher.group(3);
	Boolean encrypted = Boolean.TRUE;
	if (value.equals("encrypted")) {
	  encrypted = Boolean.TRUE;
	}
	else if (value.equals("unencrypted")) {
	  encrypted = Boolean.FALSE;
	}
	else {
	  _log.error("Unexpected token: " + line);
	  continue;
	}

	value = matcher.group(5);
	Boolean ok = Boolean.TRUE;
	if (value.equals("ok")) {
	  ok = Boolean.TRUE;
	}
	else if (value.equals("bad")) {
	  ok = Boolean.FALSE;
	}
	else {
	  _log.error("Unexpected token: " + line);
	  continue;
	}
	ProtocolPolicy pp = new ProtocolPolicy(protocolName, encrypted, ok);
	
	_protocolConfig.put(protocolName, pp);
      }
    }
    catch (IOException e) {
      _log.error("Unable to read configuration file: " + e);
    }
  }
}
