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
package org.cougaar.core.security.util;

import java.util.Collections;
import java.util.Set;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.relay.Relay;
import org.cougaar.core.util.UID;


/**
 * Shared data relay object.
 */
public class SharedDataRelay implements Relay.Source, Relay.Target {
    private MessageAddress source;
    private MessageAddress target;
    private UID uid;

    private Object content;
    private Object response;

    private transient Set targets;

    /**
     * @param content initial content
     * @param response initial response
     */
    public SharedDataRelay(UID uid, MessageAddress source, MessageAddress target, Object content, Object response) {
        this.uid= uid;
        this.source= source;
        this.target= target;

        this.content= content;
        this.response= response;

        //this.targets= targets;
        this.targets=((target != null) ? Collections.singleton(target) : Collections.EMPTY_SET);
    }

    // UniqueObject interface

    public void setUID(UID uid) {
//        throw new RuntimeException("Attempt to change UID");
      this.uid = uid;
    }

    void setTargets(Set targets) {
        this.targets= targets;
    }

    public UID getUID() {
        return uid;
    }

    // Source interface

    public Set getTargets() {
        return targets;
    }

    public Object getContent() {
        return content;
    }

    public TargetFactory getTargetFactory() {
        return SharedDataRelayTargetFactory.INSTANCE;
    }

    public int updateResponse(MessageAddress t, Object response) {
        this.response= response;
        return RESPONSE_CHANGE;
    }

    // Target interface

    public MessageAddress getSource() {
        return source;
    }

    public Object getResponse() {
        return response;
    }

    public int updateContent(Object content, Token token) {
        this.content= content;
        return CONTENT_CHANGE;
    }

  

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (!(o instanceof SharedDataRelay)) {
            return false;
        } else {
            UID u= ((SharedDataRelay) o).getUID();
            return uid.equals(u);
        }
    }

    public int hashCode() {
        return uid.hashCode();
    }

    public String toString() {
        return "(" + uid + ", " + content + ", " + response + ")";
    }

    private static final class SharedDataRelayTargetFactory implements TargetFactory, java.io.Serializable {

        public static final SharedDataRelayTargetFactory INSTANCE= new SharedDataRelayTargetFactory();

        private SharedDataRelayTargetFactory() {}

        public Relay.Target create(UID uid, MessageAddress source, Object content, Token token) {
            return new SharedDataRelay(uid, source, null, content, null);
        }

        private Object readResolve() {
            return INSTANCE;
        }
    }
}
