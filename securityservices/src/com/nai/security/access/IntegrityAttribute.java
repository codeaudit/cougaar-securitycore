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


package com.nai.security.access;

import java.io.*;

/**
 * A trust attribute which has an integer value denoting the 
 * integrity level of an associated object.
 * @version 1.0
 * @since cougaar-7.2
 */
public class IntegrityAttribute extends TrustAttribute implements Comparable, Serializable
{
    /**
     * Name of this class for TrustSet to lookup
     */
    public static String name = "IntegrityLevel";
    /**
     * The upper bound of a valid integrity level.
     */
    protected static Integer upperBound = new Integer(10);

    /**
     * The lower bound of a valid integrity level.
     */
    protected static Integer lowerBound = new Integer(1);

    /**
     * Create a new integrity attribute with the specified value.
     * @see #IntegrityLevel(Integer)
     */
    public IntegrityAttribute(int level)
    {
        this(new Integer(level));
    }

    /**
     * Create a new integrity attribute from the specified String.
     * @see #IntegrityLevel(Integer)
     */
    public IntegrityAttribute(String level)
    {
        this(new Integer(level));
    }

    /**
     * Copy constructor
     * @see #IntegrityLevel(Integer)
     */
    public IntegrityAttribute(IntegrityAttribute old)
    {
        this(new Integer(old.getIntegrityLevel().intValue()));
    }


    /**
     * Create a new integrity attribute with the specified object wrapped value.
     */
    public IntegrityAttribute(Integer value)
    {
        super(name, (Object)value);
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
     * Accessor method for getting a copy of the integrity level represented
     * by this trust attributre instance. Bounds and access control checking 
     * occur here. Also, note accessor return an Integer object not a 
     * primitive int value.
     */
    public Integer getIntegrityLevel() 
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
     * is performed in compareTo(IntegrityAttribute attribute).
     *
     * @see #compareTo(IntegrityAttribute)
     */
    public int compareTo(Object obj) {
        return compareTo((IntegrityAttribute)obj);
    }


    /**
     * Comparison method for compatibility with the Comparable interface.
     * The attribute being compared is first checked for type and then
     * the values are compared. 
     *
     * @see #getIntegrityLevel
     */
    public int compareTo(IntegrityAttribute integrity) {
        if(!(integrity instanceof IntegrityAttribute))
            throw new ClassCastException("Incompatible Integrity Level Comparison!!");
        return getIntegrityLevel().compareTo(integrity.getIntegrityLevel());                                      
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

