/*
 * <copyright>
 *  Copyright 2000-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
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
package java.util.singleton;

import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.Iterator;
import java.util.Collection;
import java.lang.ref.WeakReference;
import java.lang.ref.Reference;
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Principal;
import javax.security.auth.Subject;

//import org.cougaar.core.mts.MessageAddress;

public class EntityData {
  /**
   * The stack when the Collection or Map was created.
   */
  private Throwable _throwable;

  /**
   * The number of elements in this collection
   * We could use the size() method on the Collection or Map classes,
   * but this may be a lengthy operation.
   */
  private int       _currentSize;

  /**
   * The maximum size of the collection.
   */
  private int       _maxSize;

  /**
   * A WeakReference to the collection.
   */
  private Reference _collectionRef;

  private final AccessControlContext _acc;
  private Subject _subject;
  private Set     _principals;
  /**
   * The name of the agent that created the collection.
   */
  private String  _agentName;
  /**
   * The name of the component that created the collection.
   */
  private String  _componentName;

  /**
   * The class name of the collection.
   */
  private Class     _type;

  public EntityData(Throwable t, Object collection, Class type) {
    if ( (!(collection instanceof Collection)) &&
	 (!(collection instanceof Map)) ) {
      throw new IllegalArgumentException("Wrong type: "
					 + collection.getClass().getName());
    }
    _throwable = t;
    _collectionRef = new WeakReference(collection);
    _type = type;

    _acc = AccessController.getContext();
  }

  public int getCurrentSize(boolean update) {
    if (update) {
      updateCurrentSize();
    }
    return _currentSize;
  }

  private void updateSubject() {
    if (_subject != null) {
      // We have already retrieved the agent and component names.
      return;
    }
    _subject = (Subject)
      AccessController.doPrivileged(new PrivilegedAction() {
	public Object run() {
	  return Subject.getSubject(_acc);
	}
      });
    if (_subject != null) {
      _principals = _subject.getPrincipals();
    }
    // Update agent and component name
    try {
      if (_principals != null) {
	Iterator it = _principals.iterator();
	while (it.hasNext()) {
	  Principal p = (Principal) it.next();
	  // TODO: figure out why using RoleExecutionContext.class
	  // generates a ClassNotFoundException

	  if (p.getClass().getName().equals(
		"org.cougaar.core.security.auth.role.RoleExecutionContext")) {
	    try {
	      Method m = p.getClass().getDeclaredMethod("getAgent", null);
	      _agentName = m.invoke(p, null).toString();

	      m = p.getClass().getDeclaredMethod("getComponent", null);
	      _componentName = (String) m.invoke(p, null);
	    }
	    catch (Exception e) {
	      System.out.println("Could not get principal: " + e);
	    }
	  }
	  else if (p.getClass().getName().equals(
		"org.cougaar.core.security.auth.ChainedPrincipal")) {
	    List plist = null;
	    try {
	      Method m = p.getClass().getDeclaredMethod("getChain", null);
	      plist = (List) m.invoke(p, null);
	    }
	    catch (Exception e) {
	      System.out.println("Unable to get principal: " + e);
	    }

	    if (plist != null) {
	      switch (plist.size()) {
	      case 1:
		_agentName = plist.get(0).toString();
		break;
	      case 2:
		_agentName = plist.get(1).toString();
		break;
	      case 3:
		_componentName = plist.get(2).toString();
		_agentName = plist.get(1).toString();
		break;
	      default:
		_agentName = "chain: " + plist.size();
	      }
	    }
	  }
	}
      }
    }
    catch (Throwable e) {
      System.out.println("Error: " + e);
      e.printStackTrace();
    }
  }

  public Set getPrincipals() {
    updateSubject();
    return _principals;
  }

  public String getAgentName() {
    updateSubject();
    return _agentName;
  }

  public String getComponentName() {
    updateSubject();
    return _componentName;
  }

  public void updateCurrentSize() {
    Object o = _collectionRef.get();
    if (o != null) {
      if (o instanceof Collection) {
	_currentSize = ((Collection)o).size();
      }
      else if (o instanceof Map) {
	_currentSize = ((Map)o).size();
      }
      if (_currentSize > _maxSize) {
	_maxSize = _currentSize;
      }
    }
  }

  public int getMaxSize(boolean update) {
    if (update) {
      updateCurrentSize();
    }
    return _maxSize;
  }

  public Throwable getThrowable() {
    return _throwable;
  }

  public Class getType() {
    return _type;
  }

  public String getShortName() {
    String s = _type.getName();
    return s.substring(s.lastIndexOf('.') + 1, s.length());
  }

  public Object getCollection() {
    return _collectionRef.get();
  }
}
