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



package org.cougaar.core.security.services.acl;

// Cougaar core infrastructure
import org.cougaar.core.component.Service;
import org.cougaar.core.security.acl.trust.TrustAttribute;
import org.cougaar.core.security.acl.trust.TrustSet;

/**
 * An interface to allow Agents and Plugins limited access to the trust 
 * attribute service. <CODE>TrustAttributes</CODE> are immutable and this 
 * interface ensures that a malicious Plugin or Agent and cannot replace an 
 * entire <CODE>TrustSet</CODE>.
 */
public interface AgentTrustService extends Service
{
    /**
     * Accessor method for retrieving a trust attribute based on the object
     * and trust attribute (e.g. "IntegrityLevel", "MissionCriticality", etc.)
     * 
     * @see TrustSet
     *
     * @return an immutable trust attribute or null if either object has no 
     * valid trust set or the trust attribute type is not available in the 
     * trust set.
     */
    public TrustAttribute getTrustAttribute(Object obj, String type);

    /**
     * Assignment method for associating the specified trust attribute with 
     * a blackboard object. 
     */
    public void setTrustAttribute(Object obj, TrustAttribute trust);

}
    
