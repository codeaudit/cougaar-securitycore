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
 * A Java security manager permission to add, delete, change, or 
 * query the black board service.
 *
 * For example, the following permission only allows components in myfile.jar 
 * to query for only java.lang objects from the blackboard.
 *
 * grant codeBase "file:${org.cougaar.install.path}${/}sys${/}myfile.jar" signedBy "privileged" {
 *  ....
 *  permission org.cougaar.core.security.auth.BlackboardPermission "java.lang.*", "query";
 *  ....
 * };
 *
 */
public final class BlackboardPermission extends ServicePermission {
  private final static String[] ACTIONS = {
    "add", "change", "query", "remove"
  };

  /**
   * A blackboard permission to add, change, remove, and/or query for a particular 
   * object or package.
   *
   * @param name the class or package name (for example java.lang.String or java.lang.*)
   * @param actions add, change, remove, and/or query (* for all actions)
   */
  public BlackboardPermission(String name, String actions) {
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
