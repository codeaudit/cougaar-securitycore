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

import kaos.ontology.util.AlreadyComplement;
import kaos.ontology.util.ClassNameNotSet;
import kaos.ontology.util.RangeIsBasedOnAClass;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.policy.util.KAoSPolicyBuilderImpl;

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;

public class ServletAuthenticationParsedPolicy extends ParsedAuthenticationPolicy
{
  final String _servletClass = UltralogEntityConcepts.Servlet();
  final String _authClass = UltralogEntityConcepts.AuthenticationLevel();

  String _servletInstance;
  Set    _authInstances;

  public ServletAuthenticationParsedPolicy(String policyName,
                                           Set    auths,
                                           String servlet)
  {
    super(policyName, 
          3,
          false,
          ActorConcepts.Person(),
          UltralogActionConcepts.ServletAccess());
    _description = "All users must use ";
    {
      Iterator authIt = auths.iterator();
      String auth = (String) authIt.next();
      _description += auth;
      while (authIt.hasNext()) {
        auth = (String) authIt.next();
        _description += ", " + auth;
      }
    }
    _description += " authentication\n" + "when accessing the servlet named " 
                          + servlet;
    _servletInstance = 
      EntityInstancesConcepts.EntityInstancesOwlURL()
      + servlet;

    _authInstances = new HashSet();
    for (Iterator authIt = auths.iterator(); authIt.hasNext();) {
      String auth = (String) authIt.next();
      _authInstances.add(EntityInstancesConcepts.EntityInstancesOwlURL() 
                         + auth);
    }
  }

  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      for (Iterator authIt = _authInstances.iterator(); authIt.hasNext();) {
        String auth = (String) authIt.next();
        ontology.verifyInstanceOf(auth, _authClass);
      }
      ontology.verifyInstanceOf(_servletInstance, _servletClass);

      initiateBuildPolicy(ontology);

      for (Iterator authIt = _authInstances.iterator(); authIt.hasNext();) {
        String auth = (String) authIt.next();
        _controls.addPropertyRangeInstance
          (UltralogActionConcepts.usedAuthenticationLevel(), auth);
      }
      _controls.makeRangeComplement
               (UltralogActionConcepts.usedAuthenticationLevel(), _authClass);

      _controls.addPropertyRangeInstance
               (UltralogActionConcepts.accessedServlet(), _servletInstance);

      return _pb;
    } catch (ClassNameNotSet e) {
      throw new PolicyCompilerException(e);
    } catch (RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    } catch (AlreadyComplement e) {
      throw new PolicyCompilerException(e);
    }
  }

}
