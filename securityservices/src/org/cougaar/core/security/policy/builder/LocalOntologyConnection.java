/*
 * <copyright>
 *  Copyright 2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency *  (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

package org.cougaar.core.security.policy.builder;

import antlr.Token;

import java.io.*;
import java.util.*;

import jtp.ReasoningException;

import kaos.ontology.DefaultOntologies;
import kaos.ontology.repository.KAoSContext;
import kaos.ontology.repository.OntologyRepository;
import kaos.ontology.util.KAoSClassBuilderImpl;
import kaos.ontology.util.JTPStringFormatUtils;
import kaos.ontology.util.ValueNotSet;



public class LocalOntologyConnection extends OntologyConnection
{
  /*
   * For various reasons, this class needs intelligence.  I also
   * provide a convenience method for outsiders to load intelligence.
   */

  private static OntologyRepository  _brains = null;

  public LocalOntologyConnection()
  {
    super();
    if (_brains  == null) {
      KAoSContext kaosReasoner 
        = new KAoSContext(DefaultOntologies.ultralogOntologiesDaml);
      _brains = new OntologyRepository();
      try {
        _brains.loadOntology("http://ontology.coginst.uwf.edu/Policy.daml",
                             true);
        _brains.loadOntology
          ("http://ontology.coginst.uwf.edu/Ultralog/UltralogOntologies.daml",
           true);
      } catch (Exception e) {
        // If you need to be smart but have no brains you are screwed.
        e.printStackTrace();
        System.exit(-1);
      }
    }
  }

  public Set getInstancesOf (String conceptName) 
    throws Exception
  {
    return _brains.getInstancesOf(conceptName);
  }


  public Vector getPropertiesApplicableTo (String className)
    throws ReasoningException 
  {
    return _brains.getPropertiesApplicableTo(className);
  }

  public String getRangeOnPropertyForClass(String className, 
                                                    String propertyName) 
    throws ReasoningException
  {
    return _brains.getRangeOnPropertyForClass(className,propertyName);
  }

  public Set getSubClassesOf (String className) 
    throws Exception
  {
    return _brains.getSubClassesOf(className);
  }


  public boolean testTrue (String statement) 
    throws ReasoningException
  {
    return _brains.testTrue(statement);
  }

  public Vector getPolicies() 
    throws IOException
  {
    throw new IOException("Remote Ultralog Policies Unavailable");
  }

  public void updatePolicies (List addedPolicies,
                              List changedPolicies,
                              List removedPolicies)
    throws IOException
  {
    throw 
      new IOException("Unable to update Policies on remote domain manager");
  }
}
