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
package org.cougaar.core.security.services.auth;

import org.cougaar.core.component.Service;


/**
 * @author srosset
 *
 * This service manages the pedigree of blackboard objects.
 * There is no restriction on what component can retrieve the PedigreeService,
 * however only security components can set the pedigree. Ordinary plugins have
 * read-only access to the pedigree data.
 */
public interface PedigreeService extends Service {
  /**
   * Obtains the Pedigree of a blackboard object.
   * @param blackboardObject - the blackboard object for which pedigree data is requested.
   * @return - the Pedigree of the blackboard object.
   */
  public Pedigree getPedigree(Object blackboardObject);

  /**
   * Sets the Pedigree of a blackboard object. This method can be invoked by the security
   * services only. The Java security manager prevents ordinary plugins from
   * writing pedigree data.
   * @param blackboardObject - the blackboard object for which pedigree data should be set.
   * @param pedigree - the Pedigree of the blackboard object.
   */
  public void setPedigree(Object blackboardObject, Pedigree pedigree);
  
  /**
   * Removes the Pedigree of a blackboard object. This method can be invoked by the security
   * services only. The Java security manager prevents ordinary plugins from
   * removing pedigree data.
   * 
   * @param blackboardObject - the blackboard object for which pedigree data should be removed.
   */
  public void removePedigree(Object blackboardObject);
}
