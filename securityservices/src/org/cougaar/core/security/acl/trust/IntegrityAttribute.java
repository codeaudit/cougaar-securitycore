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
 
 
 
 
 
 


package org.cougaar.core.security.acl.trust;

import java.io.Serializable;

/**
 * A trust attribute which has an integer value denoting the 
 * integrity level of an associated object.
 * @version 1.0
 * @since cougaar-7.2
 */
public class IntegrityAttribute
  extends TrustAttribute
  implements Comparable, Serializable
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
     */
    public IntegrityAttribute(int level)
    {
        this(new Integer(level));
    }

    /**
     * Create a new integrity attribute from the specified String.
     */
    public IntegrityAttribute(String level)
    {
        this(new Integer(level));
    }

    /**
     * Copy constructor
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

