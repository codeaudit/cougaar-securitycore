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


package org.cougaar.core.security.policy.builder;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.policy.util.KAoSPolicyBuilderImpl;

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;

class AuditParsedPolicy extends ParsedAuthenticationPolicy
{
  Set _servlets;

  public AuditParsedPolicy(String policyName,
                           String userRole,
                           Set     servletNames)
  {
    super(policyName,
          3,
          false,
          userRole == null ? ActorConcepts.Person()
                           : ULOntologyNames.personActorClassPrefix + userRole,
          UltralogActionConcepts.ServletAccess());
    if (servletNames != null) {
      _servlets = new HashSet();
      for (Iterator  servletIt = servletNames.iterator(); 
           servletIt.hasNext();) {
        String servletInstance = (String) servletIt.next();
        _servlets.add(EntityInstancesConcepts.EntityInstancesOwlURL() 
                      + servletInstance);
      }
    } else {
      _servlets = null;
    }
    buildDescription(userRole, servletNames);
  }

  private void buildDescription(String userRole, Set servletNames)
  {
    _description = "Require audit for all accesses to ";

    if (servletNames != null) {
      _description += "servlet ";
      Iterator servletIt = servletNames.iterator();
      String servletInstance = (String) servletIt.next();
      _description += servletInstance;
      while (servletIt.hasNext()) {
        servletInstance = (String) servletIt.next();
        _description += ", " + servletInstance;
      }
    } else {
      _description += "all servlets";
    }

    if (userRole != null) {
      _description += " by users in role " + userRole;
    }
  }

  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      ontology.verifySubClass(getActor(), ActorConcepts.Person());
      initiateBuildPolicy(ontology);

      if (_servlets != null) {
        for (Iterator servletIt = _servlets.iterator(); servletIt.hasNext();) {
          String servletInstance = (String) servletIt.next();
          ontology.verifyInstanceOf(servletInstance, 
                                    UltralogEntityConcepts.Servlet());
          _controls.addPropertyRangeInstance
                                (UltralogActionConcepts.accessedServlet(),
                                 servletInstance);
        }
      }
      _controls.addPropertyRangeInstance
                      (UltralogActionConcepts.usedAuditLevel(), 
                        EntityInstancesConcepts.EntityInstancesOwlURL() +
                        "NoAudit");
      return _pb;
    } catch ( ClassNameNotSet e ) {
      throw new PolicyCompilerException(e);
    } catch ( RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    }
  }

}
