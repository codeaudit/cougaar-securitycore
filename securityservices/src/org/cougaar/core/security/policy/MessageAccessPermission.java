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

package org.cougaar.core.security.policy;

import java.security.BasicPermission;
import java.security.Permission;


public class MessageAccessPermission extends BasicPermission {
  private String source;
  private String target;
  private String verb;

  private static final String name = "MessageAccessPermission" ;
  
  public MessageAccessPermission(String src, String trgt, String vrb ) {
    super(MessageAccessPermission.name);
    source = src;
    target = trgt;
    verb = vrb;
  }

  
  /**
   * @return Returns the source.
   */
  public String getSource() {
    return source;
  }
  /**
   * @param source The source to set.
   */
  public void setSource( String source ) {
    this.source = source;
  }
  /**
   * @return Returns the target.
   */
  public String getTarget() {
    return target;
  }
  /**
   * @param target The target to set.
   */
  public void setTarget( String target ) {
    this.target = target;
  }
  /**
   * @return Returns the verb.
   */
  public String getVerb() {
    return verb;
  }
  /**
   * @param verb The verb to set.
   */
  public void setVerb( String verb ) {
    this.verb = verb;
  }
}
