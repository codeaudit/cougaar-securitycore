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
 
 
 
 
 
 


package org.cougaar.core.security.auth;

import java.util.Set;

/**
 * A Java security manager permission to create, read, and modify
 * objects that go on the blackboard.
 */
public final class BlackboardObjectPermission extends ServicePermission {

  private static final String[] ACTIONS = { 
    "create", "read", "write"
  };
  /**
   * Constructor
   *
   * @param name The class of blackboard object. For example, "oplan"
   * @param actions comma-separated: create, read, or write (* for all actions)
   */
  public BlackboardObjectPermission(String name, String actions) {
    super(name, actions);
  }

  protected String[] getAvailableActions() {
    return ACTIONS;
  }

  protected Set nameableObjects()
  {
    return org.cougaar.core.security.auth.role.
      AuthServiceImpl.nameableBlackboardObjects();
  }
}
