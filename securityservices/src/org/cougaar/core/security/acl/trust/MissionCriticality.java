/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Technology, Inc.
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
 * Created on October 22, 2001, 2:02 PM EDT
 */

package org.cougaar.core.security.acl.trust;


import java.io.Serializable;

public class MissionCriticality extends TrustAttribute implements Comparable, Serializable
{
    /**
     * Name of this class for TrustSet to lookup
     */
    public static String name = "MissionCriticality";
    /* 
     * The upper bound of a valid mission criticality level.
     */
    protected static Integer upperBound = new Integer(5);

    /**
     * The lower bound of a valid mission criticality level.
     */
    protected static Integer lowerBound = new Integer(1);

    /**
     * Create a new mission criticality with the specified value.
     * @see #MissionCriticality(Integer)
     */
    public MissionCriticality(int level)
    {
        this(new Integer(level));
    }

    /**
     * Create a new mission criticality from the String value.
     * @see #MissionCriticality(Integer)
     */
    public MissionCriticality(String level)
    {
        this(new Integer(level));
    }

    /**
     * Copy constructor 
     * @see #MissionCriticality(Integer)
     */
    public MissionCriticality(MissionCriticality old)
    {
	this(old.getCriticality().intValue());

    }

    /**
     * Create a new mission criticality with the specified object wrapped value.
     */
    public MissionCriticality(Integer value)
    {
        super("MissionCriticality", (Object)value);
    }

    /**
     * Read-only accessor method for the lower bound of valid integrity level
     * trust attributes.
     */
    public static int getLowerBound()
    {
        return lowerBound.intValue();
    }

    /**
     * Read-only accessor method for the upper bound of valid integrity level
     * trust attributes.
     */
    public static int getUpperBound()
    {
        return upperBound.intValue();
    }

    /**
     * Accessor method for getting a copy of the mission criticality level 
     * represented by this trust attributre instance. Bounds and access control 
     * checking occur here. Also, note accessor return an Integer object not a 
     * primitive int value.
     */
    public Integer getCriticality() 
    {
	// place access control hooks here for read access to trust attributes
        Integer level = (Integer)getValue();
	// perform bounds checking 
        if(level.compareTo(lowerBound) <= 0 && level.compareTo(upperBound) >= 0)
                return null;     
	// Integrity level out of bounds maybe throw exception instead of null
        return level;
    }

    /**
     * Generic comparison method for comparable interface. The real comparison
     * is performed in compareTo(MissionCriticality attribute).
     *
     * @see #compareTo(MissionCriticality)
     */
    public int compareTo(Object obj) {
        return compareTo((MissionCriticality)obj);
    }


    /**
     * Comparison method for compatibility with the Comparable interface.
     * The attribute being compared is first checked for type and then
     * the values are compared. 
     *
     * @see #getCriticality
     */
    public int compareTo(MissionCriticality criticality) {
        if(!(criticality instanceof MissionCriticality))
            throw new ClassCastException("Incompatible Mission Criticality Comparison!");
        return getCriticality().compareTo(criticality.getCriticality());                                      
    }

    /**
     * This method is currently NOT implemented. Trust attributes should be
     * immutable similar to String instances. If a trust attribute needs to
     * be changed a new attribute should be created and assigned to the object
     * being guarded.
     */
    public void setValue(Object obj) {}

    public String toString(){
         return super.toString();
    }

}
