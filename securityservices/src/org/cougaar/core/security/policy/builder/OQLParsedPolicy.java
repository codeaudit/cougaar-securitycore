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
import kaos.ontology.vocabulary.ActionConcepts;
import kaos.ontology.vocabulary.ActorConcepts;
import kaos.ontology.vocabulary.PolicyConstants;
import kaos.policy.util.KAoSPolicyBuilderImpl;

import org.cougaar.core.security.policy.ontology.ULOntologyNames;
import org.cougaar.core.security.policy.ontology.UltralogActionConcepts;
import org.cougaar.core.security.policy.ontology.UltralogEntityConcepts;;


public class OQLParsedPolicy
  extends ParsedAuthenticationPolicy
{
  String   _userClass;
  String   _privilege;
  Set      _dataSets;
  String   _dataSource;

  public OQLParsedPolicy(String  policyName,
                          int     priority,
                          boolean modality,
                          String  userRole,
                          String  privilege,
                          Set     dataSets,
                          String  dataSource)
    throws PolicyCompilerException
  {
    super(policyName, 
          priority,
          modality,
          userRole == null ? 
          ActorConcepts.Person : 
          ULOntologyNames.oqlRolePrefix + userRole,
          UltralogActionConcepts.OQLAction);

    _description = (modality ? "Allow" : "Deny");
    if (userRole == null) {
      _description = _description + " Any user";
    } else {
      _description = _description + " users in the role" + userRole;
    }
    _description = _description + (privilege == null ? " any": privilege) +
      " access to";
    if (dataSets == null) {
      _description = _description + " any";
      _dataSets = null;
    } else {
      _description = _description+
        (dataSets.size() ==1 ? "data set " : "data sets ");
      _dataSets = new HashSet();
      boolean firstTime = true;
      for (Iterator dataIt = dataSets.iterator();
           dataIt.hasNext();) {
        String dataSet = (String) dataIt.next();
        if (firstTime) {
          firstTime = false;
        } else {
          _description = _description + ", ";
        }
        _description = _description + dataSet;
        _dataSets.add(ULOntologyNames.oqlDataSetPrefix + dataSet);
      }
    }
    if (privilege == null) {
      _privilege = null;
    } else {
      _privilege   = ULOntologyNames.oqlPrivPrefix + privilege;
    }
    if (dataSource == null) {
      _dataSource = null;
    } else {
      _dataSource  = ULOntologyNames.oqlDataSourcePrefix + dataSource;
    }
  }


  public KAoSPolicyBuilderImpl buildPolicy(OntologyConnection ontology)
    throws PolicyCompilerException
  {
    try {
      if (_privilege != null) {
        ontology.verifyInstanceOf(_privilege, 
                                  UltralogEntityConcepts.OQLPrivilege);
      }
      if (_dataSets != null) {
        for (Iterator dataIt = _dataSets.iterator(); dataIt.hasNext();) {
          String data = (String) dataIt.next();
          ontology.verifyInstanceOf(data, UltralogEntityConcepts.OQLDataSet);
        }
      }
      if (_dataSource != null) {
        ontology.verifyInstanceOf(_dataSource, 
                                  UltralogEntityConcepts.OQLDataSource);
      }

      initiateBuildPolicy(ontology);

      if (_privilege != null) {
        _controls.addPropertyRangeInstance(
                               UltralogActionConcepts.oqlHasPrivilege,
                               _privilege);
      }
      if (_dataSets != null) {
        for (Iterator dataIt = _dataSets.iterator(); dataIt.hasNext();) {
          String data = (String) dataIt.next();
          _controls.addPropertyRangeInstance(
                           UltralogActionConcepts.oqlHasDataSet,
                           data,
                           getAuthModality() ? 
                           PolicyConstants._toClassRestriction :
                           PolicyConstants._hasClassRestriction);
        }
      }
      if (_dataSource != null) {
        _controls.addPropertyRangeInstance(
                           UltralogActionConcepts.oqlHasDataSource,
                           _dataSource);
      }
      return _pb;
    } catch (RangeIsBasedOnAClass e) {
      throw new PolicyCompilerException(e);
    } catch (ClassNameNotSet e) {
      throw new PolicyCompilerException(e);
    }
  }

}
