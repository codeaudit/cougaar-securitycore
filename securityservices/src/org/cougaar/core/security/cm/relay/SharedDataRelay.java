package org.cougaar.core.security.cm.relay;

import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.relay.Relay;
import org.cougaar.core.relay.Relay.TargetFactory;
import org.cougaar.core.util.UID;

import java.util.Collections;
import java.util.Set;


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
        throw new RuntimeException("Attempt to change UID");
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
