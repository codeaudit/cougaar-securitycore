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
 * Generic object used to encapsulate objects stored in the 
 * blackboard. Expect further functionality to be added as the
    * blackboard is secured. 
    * 
    * @author Jay Jacobs
    */
public class BlackboardObject implements Serializable
{
    /**
     * The Object to be stored in the blackboard.
     */
    Object obj;
    /**
     *  A trust attribute container for the associated object.
     */
    TrustSet set;

    /**
     * Constructor for an object, trust attribute container pair. 
     * 
     * @param o
     * @param trust
     */
    public BlackboardObject(Object o, TrustSet trust)
    {
        obj = o;
        set = trust;
    }

    /**
     * Public accessor method for the trust attribute container
     * 
     * @return A set of Trust
     */
    public TrustSet getTrustSet()
    {
        return set;
    }

    /**
     * Public accessor method for the actual object
     * 
     * @return the blackboard object
     */
    public Object getObject()
    {
        return obj;
    }

}
