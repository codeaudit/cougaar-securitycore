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


package org.cougaar.core.security.util;

import org.cougaar.core.thread.Schedulable;

public class CommunityTimerTask
  implements Runnable
{
  private long _count;
  private CommunityTimerTaskClient _client;
  private Schedulable _schedulable;

  public CommunityTimerTask(CommunityTimerTaskClient client) {
    _client = client;

    _schedulable = _client.getThreadService().getThread(this, this);
    _client.getThreadService().getThread(
      this, this).scheduleAtFixedRate(
	CommunityServiceUtil.COMMUNITY_WARNING_TIMEOUT,
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
