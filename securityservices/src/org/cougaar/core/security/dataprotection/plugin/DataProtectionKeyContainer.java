package org.cougaar.core.security.dataprotection.plugin;



import java.util.Collection;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;

public class DataProtectionKeyContainer implements UniqueObject{
	private UID uid = null;
	private Collection keyCollection;
	private String agentName;
	private long timestamp;
	
	/**
	 * @return
	 */
	public String getAgentName() {
		return agentName;
	}

	/**
	 * @param agentName
	 */
	public void setAgentName(String agentName) {
		this.agentName = agentName;
	}

	/**
	 * @return
	 */
	public Collection getKeyCollection() {
		return keyCollection;
	}

	/**
	 * @param key
	 */
	public void setKeyCollection(Collection _key) {
		this.keyCollection = _key;
	}

	/**
	 * @return
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * @param timestamp
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public UID getUID() {
		return uid;
	}

	/* (non-Javadoc)
	 * @see org.cougaar.core.util.UniqueObject#setUID(org.cougaar.core.util.UID)
	 */
	public void setUID(UID id) {
		uid = id;
		
	}

}
