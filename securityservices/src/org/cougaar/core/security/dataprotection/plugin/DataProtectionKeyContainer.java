package org.cougaar.core.security.dataprotection.plugin;



import java.util.Collection;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;

public class DataProtectionKeyContainer implements UniqueObject{
	private UID uid = null;
        private byte[] key;
	private String agentName;
	private long timestamp;
	
        public DataProtectionKeyContainer(String agent, 
          byte[] bytes, long timestamp) {
          agentName = agent;
          key = bytes;
          this.timestamp = timestamp;
        }

        public void setUID(UID uid) {
          this.uid = uid;
        }

	/**
	 * @return
	 */
	public String getAgentName() {
		return agentName;
	}

	/**
	 * @return
	 */
	public byte[] getKey() {
		return key;
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

}
