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

import org.cougaar.core.component.*;
import org.cougaar.core.mts.*;
import org.cougaar.core.society.*;

/**
 * A proxy base for performing access control on messages. The proxy protects
 * the MessageTransportServer from the Agent and vice versa. Each Agent should
 * have a unique proxy instance.
 * @author Jay Jacobs
 * @version 1.0
 */ 
public class MessageTransportServiceProxy 
    implements MessageTransportClient,  MessageTransportService, Service 
{

    /**
     * Stored a local copy of the clients id. 
     */
    public String uid;

    /**
     * Flag to determine whether to log messages that have been
     * ssent or received. 
     */
    private boolean loggingEnabled = 
        Boolean.getBoolean(System.getProperty("our.cougaar.core.security.LogMessages","false"));
                                          
    /**
     * Log of messages that have been received by the client
     */
    protected MessageLog receiveLog;

    /**
     * Log of messages that have been sent to message transport
     */
    protected MessageLog sendLog;

    /**
     *  The server which is a MessageTransportServerProxy.
     */
    protected MessageTransportService server;

    /**
     * A class which implements MessageClient. Examples include Agent or Node.
     */
    protected MessageTransportClient client;
                        
    /**
     * Default contructor of the objects being mediated for.
     * 
     * @param server
     * @param client
     */
    public MessageTransportServiceProxy
        (MessageTransportService server, MessageTransportClient client)
    {
        this.client = client;
        // sanity check in case client changes address
        uid = client.getMessageAddress().toAddress(); 
        this.server = server;
    }

    /**
     * Accessor method for unique identifier.
     * 
     * @return the MessageAddress of this proxy's client
     */
    public String getUID() { return uid; }

    // Message TransportCLient Methods

    public MessageAddress getMessageAddress() 
    { 
        // place access control checking here
        return client.getMessageAddress();
    }
    
    /**
     * processes messages being sent from the client to the 
     * server (on to the network).
     * 
     * @param msg
     */
    public void receiveMessage(Message msg) 
    {
        // log incoming message if necessary
        if(loggingEnabled)receiveLog.add(msg);
        // send message on to the agent
        client.receiveMessage(msg);
    }

    // Message Transport Server Proxy methods

    public void addMessageTransportWatcher(MessageTransportWatcher watcher)
    {
        //place access control for watcher adding here
        //server.addMessageTransportWatcher(watcher);
    }


    /**
     * checks with the transport service to see if the address 
     * is known.
     * 
     * @param addr
     * @return 
     */
    public boolean addressKnown(MessageAddress addr)
    {
        //place access control for querying known addresses here
        return server.addressKnown(addr);
    }



    /**
     * accessor method the message transport services identifier
     * 
     * @return 
     */
    public String getIdentifier()
    {
        return server.getIdentifier();
    }

    /**
     * method to delegate the registration request to the
     * real server.
     * 
     * @param client
     */
    public void registerClient(MessageTransportClient client)
    {
        server.registerClient(client);
    }

    public void unregisterClient(MessageTransportClient client)
    {
	server.unregisterClient(client);
    }

    public java.util.ArrayList flushMessages()
    {
	return server.flushMessages();
    }

    /**
     * perform access control on this message and log it 
     * if necessary. Access control is performed in child 
     * classes.
     * 
     * @param msg
     */
    public void sendMessage(Message msg)
    {
        //log outgoing message here
        if(loggingEnabled)sendLog.add(msg);
        //send message on to the message transport
        server.sendMessage(msg);
    }

}
