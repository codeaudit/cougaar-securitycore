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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.mts.MessageAttributes;
import org.cougaar.core.mts.MessageTransportClient;
import org.cougaar.core.node.NodeIdentificationService;
import org.cougaar.core.security.util.ServletRequestUtil;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
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
  
  private LoggingService _log;
  private URI _nodeURI;
  private Map _links = new Hashtable();
  private ServletService _servletService;
  protected int _port = -1;
  protected String _nodeName;
  public final String SERVLET_URI = "/httpmts";
     
  /**
   * Called via introspection by the Container. We use it to get the
   * node name for the HTTP(S) URI.
   */
  public void setNodeIdentificationService(NodeIdentificationService nis) {
    if (nis != null) {
      _nodeName = nis.getMessageAddress().toAddress();
    }
  } //setNodeIdentificationService(NodeIdentificationService nis)

  /**
   * Initialize the LinkProtocol and register listeners for the ServletService and 
   * BlackboardService if those services aren't currently available.
   */
  public void load() {
    super.load();
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    // the ServletService here is the RootServletService
    // NOTE: only the HEAD contains the RootServletService class.
    // we must change this to oorg.cougaar.lib.web.service.RootServletService
    // instead of ServletService in HEAD.
    if (sb.hasService(ServletService.class)) {
      init(sb);
    } else {
      sb.addServiceListener(new ServiceAvailableListener(){
          public void serviceAvailable(ServiceAvailableEvent ae) {
            if (ServletService.class.isAssignableFrom(ae.getService())) {
              init(ae.getServiceBroker());
              ae.getServiceBroker().removeServiceListener(this);
            }
          }
        });
    }   
    // we want the servlet service, but it's loaded after the MTS.
    // Also, we want the agent's proxy to the node-level
    // ServletService.  The blackboard is loaded late enough, so we
    // wait 'til then...  (hack for all versions before 11.2 HEAD)
    if (sb.hasService(BlackboardService.class)) {
      registerServlet(sb);
    } else {
      sb.addServiceListener(new ServiceAvailableListener(){
          public void serviceAvailable(ServiceAvailableEvent ae) {
            if (BlackboardService.class.isAssignableFrom(ae.getService())) {
              registerServlet(ae.getServiceBroker());
              ae.getServiceBroker().removeServiceListener(this);
            }
          }
        });
    }   
  } //load()
  
  /**
   * We release the ServletService here because in doing so,
   * the ServletService.unregisterAll() is invoked. 
   */
  public void unload() {
    getServiceBroker().releaseService(this, ServletService.class, _servletService);  
    super.unload();
  } //unload() 
  
  // #########################################################################
  // THE FOLLOWING SET OF METHODS CAN BE OVERWRITTEN by various HTTP 
  // LinkProtocols.  For example, a SOAPLinkProtocol.
  /**
   * Get the WP Entry Type for registering and querying for WP entries.
   */
  public String getWPEntryType() {
    return "-HTTP"; 
  } //getWPEntryType()
  
  /**
   * Get the protocol to use for http connections.
   */
  public String getProtocol() {
    return "http";
  } //getProtocol() 
  
  /**
   * Used to set the port.
   */
  protected void setPort(ServletService ss) {
    _port = ss.getHttpPort();
  } //setPort(ServletService ss
  
  /**
   * determined the underlying socket is encrypted.
   */
  protected Boolean usesEncryptedSocket() {
	  return Boolean.FALSE;
  } //usesEncryptedSocket()
  
  /**
   * Returns 500 (hard-coded value less than RMI).
   */
  protected int computeCost(AttributedMessage message) {
	  return 500;
  }
  
  protected String getPath() {
    return SERVLET_URI;
  }
  
  // create servlet that handle java serialized messages over HTTP 
  protected Servlet createServlet() {
    return new HTTPLinkProtocolServlet();
  }
  
  // create destination link to stream java serialized messages over HTTP
  protected DestinationLink createDestinationLink(MessageAddress addr) {
    return new HTTPDestinationLink(addr); 
  }
  // #########################################################################
  
  /**
   * Set the Port and URI
   */
  private void init(ServiceBroker sb) {
    ServletService servletService = (ServletService) 
      sb.getService(this, ServletService.class, null);
    setPort(servletService);
    setURI();
    sb.releaseService(this, ServletService.class, servletService); 
  } //init(ServiceBroker sb)

  /**
   * Register the Servlet that will handle the messages on the receiving end.
   */
  private void registerServlet(ServiceBroker sb) {
    _servletService = (ServletService) 
      sb.getService(this, ServletService.class, null);
    try {
      if(_log.isDebugEnabled()) {
        _log.debug("registering " + getPath() + " with " + _servletService);
      }
      _servletService.register(getPath(), createServlet());
    } catch(IllegalArgumentException iae) {
      // an IllegalArgumentException could occur if the servlet path has already
      // been registered.  for example, both the HTTP and HTTPS LinkProtocols
      // could be installed.
      _log.warn(getPath() + " already register.");
    } catch(Exception e) {
      _log.error(getPath() + " failed to register.");
    }
    
    // we release the ServletService in the unload() method because in doing so,
    // the ServletService.unregisterAll() is invoked. 
  } //registerServlet(ServiceBroker sb) {
 
  /**
   * Sets the HTTP URI that other Nodes should use for sending messages.
   */
  private void setURI() {
    if (_nodeName == null) {
      ServiceBroker sb = getServiceBroker();
      NodeIdentificationService nis = (NodeIdentificationService)
        sb.getService(this, NodeIdentificationService.class, null);
      _nodeName = nis.getMessageAddress().toAddress();
      sb.releaseService(this, NodeIdentificationService.class, nis);
    }
    try {
      InetAddress me = InetAddress.getLocalHost();
      _nodeURI = new URI(getProtocol() + "://" + me.getHostName() + ':' + 
                         _port + "/$" + _nodeName + getPath());
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
        link = createDestinationLink(addr);
        link = (DestinationLink) attachAspects(link, DestinationLink.class);
        _links.put(addr, link);
      }
      return link;
    }
  } //getDestinationLink(MessageAddress destination)

  public void registerClient(MessageTransportClient client) {
    MessageAddress addr = client.getMessageAddress();
    getNameSupport().registerAgentInNameServer(_nodeURI, addr, getWPEntryType());
  } //registerClient(MessageTransportClient client)

  public void unregisterClient(MessageTransportClient client) {
    MessageAddress addr = client.getMessageAddress();
    getNameSupport().unregisterAgentInNameServer(_nodeURI, addr, getWPEntryType());
  } //unregisterClient(MessageTransportClient client)

  protected class HTTPDestinationLink implements DestinationLink {
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
    
    public HTTPDestinationLink(MessageAddress target) {
      _target = target;
    } //HTTPDestinationLink(MessageAddress target)

    public void addMessageAttributes(MessageAttributes attrs) {
     // attribute used securityservices to determine whether or not
     // to encrypt the raw message.
     attrs.addValue(MessageAttributes.ENCRYPTED_SOCKET_ATTRIBUTE,
    			   usesEncryptedSocket());
    } //addMessageAttributes(MessageAttributes attrs)

    public int cost(AttributedMessage message) {
      try {
        ensureURL();
        return computeCost(message); 
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
        //e.printStackTrace();
        throw new CommFailureException(e);
      }
    } //forwardMessage(AttributedMessage message)

    /**
     * If the destination URL is not available then a White Pages
     * lookup is started if one is not currently in progress and
     * and exception is thrown. Otherwise the target URL
     * is returned.
     */
    protected URL ensureURL() 
      throws NameLookupException, UnregisteredNameException {
      synchronized (_wpCallback) {
        if (_url == null) {
          if (!_wpPending) {
            _wpPending = true;
            getNameSupport().lookupAddressInNameServer(_target, getWPEntryType(),
                                                       _wpCallback);
          } 
          throw new UnregisteredNameException(_target);
        }
        return _url;
      }
    } //ensureURL() 
    
    // this method streams serialized java objects over HTTP, and could be overridden 
    // if streaming format is different (e.g., SOAP)
    protected Object postMessage(URL url, AttributedMessage message) 
      throws IOException, ClassNotFoundException, UnknownHostException {
      HttpURLConnection conn = null;
      ObjectInputStream ois = null;
      try {
        if(_log.isDebugEnabled()) {
          _log.debug("sending " + message.getRawMessage().getClass().getName() + "(" + 
            message.getOriginator() + "->" + message.getTarget() + ") to " + url);
        }
        // NOTE:
        // Performing a URL.openConnection() does not necessarily open a new socket.
        // Specifically, HttpUrlConnection reuses a previously opened socket to
        // the target, and there is no way to force the underlying socket to close.
        // From the javadoc: "Calling the disconnect() method may close the underlying
        // socket if a persistent connection is otherwise idle at that time."
        //
        // However, This could pose a resource consumption issue.  If this is the 
        // case, we need to use a different HTTP Client implementation such as 
        // Jakarta's Common HTTP Client.
        conn = ServletRequestUtil.sendRequest(url.toString(), message, "POST");
        ois = new ObjectInputStream(conn.getInputStream());
        return ois.readObject();
      } catch(Exception e) {
        _log.debug("Exception in postMessge", e);
      } finally {
        if (ois != null) {
          ois.close();
        }
      }
      return null;
    } //postMessage(URL url, AttributedMessage message)
  } //class HTTPDestinationLink
  
  
  protected class HTTPLinkProtocolServlet extends HttpServlet {
    
    public void usage(HttpServletResponse resp) 
      throws IOException {
      resp.setContentType("text/html");
      PrintWriter out = resp.getWriter();
      out.println("<html><head><title>HTTP MTS Servlet</title></head>");
      out.println("<body><h1>HTTP MTS Servlet</h1>");
      out.println("This Servlet is only for use by the HTTPLinkProtocol.");
      out.println("</body></html>");
    }
    
    public void doGet(HttpServletRequest req, HttpServletResponse resp) 
      throws ServletException, IOException {
        usage(resp);
    } //doGet(HttpServletRequest req, HttpServletResponse resp) 
   
    public void doPost(HttpServletRequest req, HttpServletResponse resp) 
      throws ServletException, IOException {
      Object result = null;
  
      if(_log.isDebugEnabled()) {
        debugHeaders(req);
      }

      try {
        Object obj = readMessage(req.getInputStream(), getContentLength(req));
        if (!(obj instanceof AttributedMessage)) {
          Exception e = 
            new IllegalArgumentException("send message content of class: " +
                                         obj.getClass().getName());
          result = new CommFailureException(e);
          if(_log.isDebugEnabled()) {
            _log.debug("object not AttributedMessage but is a " + 
              obj.getClass().getName(), e);
          }
        } else {
          AttributedMessage message = (AttributedMessage) obj;
          // deliver the message by obtaining the MessageDeliverer from the LinkProtocol
          result = getDeliverer().deliverMessage(message, message.getTarget());
          if(_log.isDebugEnabled()) {
            _log.debug("DELIVERED " + message.getRawMessage().getClass().getName() 
              + "(" + message.getOriginator() + "->" + message.getTarget() + 
              ") with result=" + result);
          }
        }
      } catch (MisdeliveredMessageException e) {
        result = e;
      } catch (Exception e) {
        result = new CommFailureException(e);
      } finally {
        // return result
        resp.setContentType("application/x-www-form-urlencoded");
        ObjectOutputStream oos = new ObjectOutputStream(resp.getOutputStream());
        oos.writeObject(result);
        oos.flush();
      }
    } //doPost(HttpServletRequest req, HttpServletResponse resp)
    
    // this method reads a serialized java object from the HTTP input stream, but can be 
    // overridden to read different message formats (e.g., SOAP messages).
    protected Object readMessage(InputStream is, int mlen)
      throws Exception {
        // NOTE: Not sure if this is a hack or a solution to a problem, but we
        // need to wrap the ServletInputStream in a BufferedInputStream.  Otherwise,
        // bytes on the stream disappear(?) and reading from the input stream hangs
        // during readObject->readExternal->finishInput->verifySignature.
        ObjectInputStream ois = new ObjectInputStream(
          new BufferedInputStream(is, mlen));
        Object obj = ois.readObject();
        if(_log.isDebugEnabled()) {
          _log.debug("read object from input stream");
        }
        ois.close();
        return obj;
    }
    
    private int getContentLength(HttpServletRequest req) {
      int contentLength = 512;
      try {
        String header = req.getHeader("Content-length");
        if(header != null) {
          contentLength = Integer.parseInt(header);
        } else {
          if(_log.isDebugEnabled()) {
            _log.debug("Content-length not available"); 
          }
        }
      } catch(NumberFormatException nfe) {
        _log.warn("Cannot parse Content-length", nfe);
      }
      return contentLength;
    } //getContentLength(HttpServletRequest req)
    
    private void debugHeaders(HttpServletRequest req) {
      _log.debug("########## HTTP HEADERS ##########");
        Enumeration e = req.getHeaderNames();
        while(e.hasMoreElements()) {
          String hdr = (String)e.nextElement();
          _log.debug(hdr + ": " + req.getHeader(hdr));
        }
        _log.debug("##################################"); 
    } //debugHeaders(HttpServletRequest req)
  } //class HttpLinkProtocolServlet
}
