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

package org.cougaar.core.security.util;

import java.util.TimerTask;
import org.cougaar.core.thread.Schedulable;

public class CommunityTimerTask
  extends TimerTask
{
  private long _count;
  private CommunityTimerTaskClient _client;
  private Schedulable _schedulable;

  public CommunityTimerTask(CommunityTimerTaskClient client) {
    _client = client;

    _schedulable = _client.getThreadService().getThread(this, this);
    _client.getThreadService().scheduleAtFixedRate(
      this, CommunityServiceUtil.COMMUNITY_WARNING_TIMEOUT,
      CommunityServiceUtil.COMMUNITY_WARNING_TIMEOUT);

  }

  public void run() {
    _count++;
    synchronized (_client.getLock()) {
      if (_client.getCommunities() == null ||
	  _client.getCommunities().isEmpty()) {
	if (_client.getLogService().isWarnEnabled()) {
	  _client.getLogService().warn(
	    "Agent is not part of any community: " + 
	    _client.getAddress()
	    + " - " + _count + " checks so far - Timeout=" +
	    CommunityServiceUtil.COMMUNITY_WARNING_TIMEOUT / 1000
	    + "s");
	}
	// Reschedule to get warning later.
	_schedulable.cancel();
      }
      else {
	if (_client.getLogService().isDebugEnabled()) {
	  _client.getLogService().debug("Got security community");
	}
      }
    }
  }
}
