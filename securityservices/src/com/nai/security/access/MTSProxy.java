/*
 * <copyright>
 *  Copyright 1997-2001 (Orig Developer Company Name Here)
 *  under sponsorship of the Defense Advanced Research Projects
 *  Agency (DARPA).
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS 
 *  PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR 
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF 
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT 
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT 
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL 
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS, 
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR 
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.  
 * 
 * </copyright>
 *
 * CHANGE RECORD
 * - 
 */

package com.nai.security.access;

import java.io.*;
import java.text.*;
import java.util.*;

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
public class MTSProxy
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
    private static boolean loggingEnabled; 
        
    /** Property to use for configuring a log file name */
    private static final String LOG_PROPERTY = 
	"org.cougaar.core.security.MTSProxyLog";

    /** Printstream for debugging and error logging */
    protected PrintStream log;

                                          
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
    public MTSProxy
	(MessageTransportService server, MessageTransportClient client)
    {
	File logFile;
	String logMessages = System.getProperty(
	    "org.cougaar.core.security.LogMsgs","false");			    
        this.client = client;
        this.server = server;
        // sanity check in case client changes address
        uid = client.getMessageAddress().toAddress(); 
	loggingEnabled = logMessages.equalsIgnoreCase("true");
	try {
	    if(loggingEnabled) {
		logFile = new File(System.getProperty(LOG_PROPERTY, "MTSlog.") 
				   + uid); 
		System.out.print(" (logfile = " + logFile + ") ");
		log = new PrintStream(new FileOutputStream(logFile));
	    }
	    else {
		log = System.out;
	    }
	}
	catch(Exception ex) { // if we cannot open the file don't use it...
	    if(log == null)log = System.out;
	    log.println("Cannot open file, reverting to stdout...");
	    ex.printStackTrace(log);
	}
	if(loggingEnabled) {
	    log.print("<logtime>");
	    log.print(DateFormat.getDateInstance().format(new Date()));
	    log.println("</logtime>");
	    log.print("<client>"); log.print(uid); log.println("</client>");
	    log.flush();
	}
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
        if(loggingEnabled){
	    log.print("<receiveMessage>\n\t");
	    log.println(msg.toString());
	    log.println("</receiveMessage>");
	    log.flush();
	}
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
        if(loggingEnabled) {
	    log.print("<sendMessage>\n\t");
	    log.println(msg.toString());
	    log.println("<sendMessage>");
	    log.flush();
	}
        //send message on to the message transport
        server.sendMessage(msg);
    }

}










