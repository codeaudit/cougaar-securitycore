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
 
package org.cougaar.core.security.mts;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.Hashtable;
import java.util.Map;

import org.apache.catalina.util.Base64;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.service.ServletService;
import org.cougaar.core.service.wp.AddressEntry;
import org.cougaar.core.service.wp.Callback;
import org.cougaar.core.service.wp.Response;
import org.cougaar.mts.base.CommFailureException;
import org.cougaar.mts.base.DestinationLink;
import org.cougaar.mts.base.LinkProtocol;
import org.cougaar.mts.base.MisdeliveredMessageException;
import org.cougaar.mts.base.NameLookupException;
import org.cougaar.mts.base.UnregisteredNameException;
import org.cougaar.mts.std.AttributedMessage;

public class HTTPLinkProtocol extends LinkProtocol {
  private   URI     _nodeURI;
  private   Map     _links       = new Hashtable();
  private   int     _httpPort    = -1;
  protected String  _nodeName;
  protected String  _servletPath = "/httpmts";

  public static final String PROTOCOL = "-HTTP";
  private static HTTPLinkProtocol _linkProtocol;
  
  static HTTPLinkProtocol getLink() {
    return _linkProtocol;
  }

  public HTTPLinkProtocol() {
    _linkProtocol = this;
  } //HTTPLinkProtocol()

  /**
   * Start looking for the ServletService so that we can get the local
   * HTTP port number.
   */
  public void load() {
    super.load();
    ServiceBroker sb = getServiceBroker();
    if (sb.hasService(ServletService.class)) {
      setSS(sb);
    } else {
      sb.addServiceListener(new ServiceAvailableListener(){
          public void serviceAvailable(ServiceAvailableEvent ae) {
            if (ae.getService() == ServletService.class) {
              setSS(ae.getServiceBroker());
              ae.getServiceBroker().removeServiceListener(this);
            }
          }
        });
    }
  } //load()

  /**
   * Get the HTTP Port from the ServletService
   */
  private void setSS(ServiceBroker sb) {
    ServletService servletService = (ServletService) 
      sb.getService(this, ServletService.class, null);
    _httpPort = servletService.getHttpPort();
    sb.releaseService(this, ServletService.class, servletService);
    setURI();
  } //setSS(ServiceBroker sb)

  /**
   * Called via introspection by the Container. We use it to get the
   * node name for the HTTP URI.
   */
  public void setNodeIdentificationService(NodeIdentificationService nis) {
    if (nis != null) {
      _nodeName = nis.getMessageAddress().toAddress();
      setURI();
    }
  } //setNodeIdentificationService(NodeIdentificationService nis)

  /**
   * Sets the HTTP URI that other Nodes should use for sending messages.
   */
  private void setURI() {
    if (_httpPort == -1 || _nodeName == null) {
      return;
    }
    try {
      InetAddress me = InetAddress.getLocalHost();
      _nodeURI = new URI("http://" + me.getHostName() + ':' + 
                         _httpPort + "/$" + _nodeName + _servletPath);
    } catch (Exception e) {
      e.printStackTrace();
    }
  } //setURI()

  public boolean addressKnown(MessageAddress address) {
    return (_links.get(address.toAddress()) != null);
  } //addressKnown(MessageAddress address)

  public DestinationLink getDestinationLink(MessageAddress destination) {
    MessageAddress addr = destination.getPrimary();
    synchronized (_links) {
      DestinationLink link = (DestinationLink) _links.get(addr);
      if (link == null) {
        link = new HTTPDestinationLink(addr);
        link = (DestinationLink) attachAspects(link, DestinationLink.class);
        _links.put(addr, link);
      }
      return link;
    }
  } //getDestinationLink(MessageAddress destination)

  public void registerClient(MessageTransportClient client) {
    MessageAddress addr = client.getMessageAddress();
    getNameSupport().registerAgentInNameServer(_nodeURI, addr, PROTOCOL);
  } //registerClient(MessageTransportClient client)

  public void unregisterClient(MessageTransportClient client) {
    MessageAddress addr = client.getMessageAddress();
    getNameSupport().unregisterAgentInNameServer(_nodeURI, addr, PROTOCOL);
  } //unregisterClient(MessageTransportClient client)

  MessageAttributes deliverMessage(AttributedMessage message) 
    throws MisdeliveredMessageException {
    return getDeliverer().deliverMessage(message, message.getTarget());
  } //deliverMessage(AttributedMessage message) 

  /**
   * Converts an object to a pseudo-Base64-encoded byte block
   */
  static byte[] convertToBytes(Object obj) throws IOException {
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    try {
      ObjectOutputStream oos = new ObjectOutputStream(bout);
      oos.writeObject(obj);
      oos.close();
    } catch (Exception e) {
      e.printStackTrace();
    }
    byte buf[] = Base64.encode(bout.toByteArray());
    // Base64 encoding uses + and =. in HTTP POST, these are interpreted
    for (int i = 0; i < buf.length; i++) {
      if (buf[i] == '+') {
        buf[i] = '-';
      } else if (buf[i] == '=') {
        buf[i] = '*';
      }
    }
    return buf;
  } //convertToBytes(Object obj)

  /**
   * Converts a pseudo-Base64-encoded byte block to an Object
   */
  static Object convertFromBytes(byte[] buf) throws IOException {
    // Base64 encoding uses + and =. in HTTP POST, these are interpreted
    for (int i = 0; i < buf.length; i++) {
      if (buf[i] == '-') {
        buf[i] = '+';
      } else if (buf[i] == '*') {
        buf[i] = '=';
      }
    }
    try {
      buf = Base64.decode(buf);
      ByteArrayInputStream bin = new ByteArrayInputStream(buf);
      ObjectInputStream ois = new ObjectInputStream(bin);
      Object obj = ois.readObject();
      return obj;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  } //convertFromBytes(byte[] buf)

  private class HTTPDestinationLink implements DestinationLink {
    private MessageAddress _target;
    private URL            _url;
    private boolean        _wpPending = false;
    private Callback       _wpCallback = new Callback() {
        public void execute(Response response) {
          Response.Get rg = (Response.Get) response;
          AddressEntry entry = rg.getAddressEntry();
          synchronized (this) {
            _wpPending = false;
            try {
              if (entry != null && entry.getURI() != null) {
                _url = entry.getURI().toURL();
              }
            } catch (MalformedURLException e) {
              // this shouldn't happen.
              e.printStackTrace();
            }
          }
        }
      };

    private final byte[] PREMSG = { (byte) 'm', (byte) '=' };

    public HTTPDestinationLink(MessageAddress target) {
      _target = target;
    } //HTTPDestinationLink(MessageAddress target)

    public void addMessageAttributes(MessageAttributes attrs) {
      // no attributes needed.
    } //addMessageAttributes(MessageAttributes attrs)

    /**
     * Returns 500 if the destination is currently reachable.
     * If not then Integer.MAX_VALUE is returned.
     */
    public int cost(AttributedMessage message) {
      try {
        ensureURL();
        return 500;  // arbitrary, but smaller than RMI
      } catch (Exception e) {
        // If the remote URI doesn't exist, then we can't reach it, yet.
        // use another protocol instead.
        return Integer.MAX_VALUE;
      }
    } //int cost(AttributedMessage message)

    public boolean isValid() {
    	return true;
    }

    public MessageAddress getDestination() {
      return _target;
    } //getDestination()

    public Class getProtocolClass() {
      return HTTPLinkProtocol.class;
    } //getProtocolClass()

    public Object getRemoteReference() {
      return _url;
    } //getRemoteReference()

    public boolean retryFailedMessage(AttributedMessage message, 
                                      int retryCount) {
      return true;
    } //retryFailedMessage(AttributedMessage message, int retryCount)

    /**
     * Posts the message to the target Agent's HTTP Link Protocol Servlet.
     */
    public MessageAttributes forwardMessage(AttributedMessage message) 
      throws NameLookupException, UnregisteredNameException, 
      CommFailureException, MisdeliveredMessageException {
      URL url = ensureURL();
      try {
        Object response = postMessage(url, message);
        if (response instanceof MessageAttributes) {
          return (MessageAttributes) response;
        } else if (response instanceof MisdeliveredMessageException) {
          synchronized (_wpCallback) {
            _url = null;
          }
          throw (MisdeliveredMessageException) response;
        } else {
          throw new CommFailureException((Exception) response);
        }
      } catch (Exception e) {
        throw new CommFailureException(e);
      }
    } //forwardMessage(AttributedMessage message)

    /**
     * If the destination URL is not available then a White Pages
     * lookup is started if one is not currently in progress and
     * and exception is thrown. Otherwise the target URL
     * is returned.
     */
    private URL ensureURL() 
      throws NameLookupException, UnregisteredNameException {
      synchronized (_wpCallback) {
        if (_url == null) {
          if (!_wpPending) {
            _wpPending = true;
            getNameSupport().lookupAddressInNameServer(_target, PROTOCOL,
                                                       _wpCallback);
          } else {
          }
          throw new UnregisteredNameException(_target);
        }
        return _url;
      }
    } //ensureURL() 

    private Object postMessage(URL url, AttributedMessage message) 
      throws IOException, ClassNotFoundException, UnknownHostException {
      byte[] buf = convertToBytes(message);
      URLConnection conn = url.openConnection();
      OutputStream os = null;
      InputStream  is = null;
      try {
        conn.setDoOutput(true);
        os = conn.getOutputStream();
        os.write(PREMSG);
        os.write(buf);
        os.flush();
        is = conn.getInputStream();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int bytes;
        byte[] b = new byte[1000];
        while ((bytes = is.read(b)) != -1) {
          bout.write(b, 0, bytes);
        }
        return convertFromBytes(bout.toByteArray());
      } finally {
        if (os != null) {
          os.close();
        }
        if (is != null) {
          is.close();
        }
      }
    } //postMessage(URL url, AttributedMessage message) 
  } //class HTTPDestinationLink
}
