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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;

import java.util.HashSet;
import java.util.Set;

import org.cougaar.core.security.policy.ontology.EntityInstancesConcepts;
import org.cougaar.util.ConfigFinder;

import org.apache.log4j.Logger;

public class VerbBuilder
{
  private static Logger _log 
    = Logger.getLogger("org.cougaar.core.security.policy.builder.VerbBuilder");
  private static Set _ontVerbs;

  public final static Set hasSubjectValues()
  {
    if (_ontVerbs == null) {
      initializeVerbs();
    }
    return _ontVerbs;
  }

  public final static String  kaosVerbFromVerb(String verb)
  {
    if (verb == null) {
      verb = EntityInstancesConcepts.NoVerb();
    } else {    
      verb = EntityInstancesConcepts.EntityInstancesOwlURL() + verb;
    }
    if (hasSubjectValues().contains(verb)) {
      return verb;
    } else { 
      return EntityInstancesConcepts.EntityInstancesOwlURL() + "OtherVerb";
    }
  }

  private final static void initializeVerbs()
  {
    try {
      ConfigFinder cf = ConfigFinder.getInstance();
      _ontVerbs       = new HashSet();

      _ontVerbs.add(EntityInstancesConcepts.OtherVerb());
      _ontVerbs.add(EntityInstancesConcepts.NoVerb());


      InputStream verbIS = cf.open("OwlMapVerbs");
      if (verbIS == null) {
        _log.error("Could not find verb mapping file");
        return;
      }
      BufferedReader verbReader
        = new BufferedReader(new InputStreamReader(verbIS));
      String line;
      while ((line = verbReader.readLine()) != null) {
        if (line.startsWith("#")) { continue; }
        _ontVerbs.add(EntityInstancesConcepts.EntityInstancesOwlURL() + line);
      }
    } catch (IOException ioe) {
      _log.error("Could not retrieve verbs");
    }
  }
}
