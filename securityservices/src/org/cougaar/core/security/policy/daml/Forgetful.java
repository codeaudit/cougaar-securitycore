/*
 * <copyright>
 *  Copyright 1997-2001 Networks Associates Inc
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

package org.cougaar.core.security.policy.daml;

import com.hp.hpl.jena.daml.*;
import com.hp.hpl.jena.daml.common.DAMLModelImpl;
import com.hp.hpl.jena.rdf.query.parser.Literal;
import com.hp.hpl.mesa.rdf.jena.common.*;
import com.hp.hpl.mesa.rdf.jena.mem.ModelMem;
import com.hp.hpl.mesa.rdf.jena.model.*;
import com.hp.hpl.mesa.rdf.jena.rdb.RDFRDBException;
import com.hp.hpl.mesa.rdf.jena.vocabulary.*;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.lang.String;
import java.util.Hashtable;

public class Forgetful {
    static String anonstring = "http://ontology.coginst.uwf.edu/PolicyInstances.daml#";

    public static void main(String args[]) 
	throws RDFException, FileNotFoundException {

        if (args.length != 2) {
            System.err.println(
		   "Both arguments should be a paths to a daml Ontology");
            System.exit(-1);
        }


	DAMLModel model1 = new DAMLModelImpl();
	model1.getLoader().setLoadImportedOntologies(false);
	FileReader desc1 = new FileReader(args[0]);
	model1.read(desc1,"");

	DAMLModel model2 = new DAMLModelImpl();
	model2.getLoader().setLoadImportedOntologies(false);
	FileReader desc2 = new FileReader(args[1]);
	model2.read(desc2,"");

	beautify(model1);

	if (copy(model1).equals(copy(model2))) {
	    System.out.println("They are equal");
	} else {
	    System.out.println("They are not equal");
	}
    }

    static public void beautify(Model m) throws RDFException
    {
	copy(m).write(new PrintWriter(System.out), "RDF/XML-ABBREV");
    }

    static public Model copy(Model m) throws RDFException
    {
	Model     out = new ModelMem();
	Hashtable h   = new Hashtable();

	// list the statements in the graph
	StmtIterator iter = m.listStatements();
            
	// print out the predicate, subject and object of each statement
	while (iter.hasNext()) {
	    Statement stmt      = iter.next();         // get next statement
	    Resource  subject   = stmt.getSubject();   // get the subject
	    Resource  newsubject;
	    Property  predicate = stmt.getPredicate(); // get the predicate
	    Property  newpredicate;
	    RDFNode   object    = stmt.getObject();    // get the object
	    RDFNode   newobject;

	    if (predicate.getLocalName().equals("hasUpdateTimeStamp")) {
		continue;
	    }

	    //    System.out.println("-------------------------------------");
	    //    System.out.println("SUBJECT");
	    if ((newsubject = (Resource) h.get(subject)) == null) {
		newsubject = copySubject(subject, out);
		h.put(subject, newsubject);
	    }

	    //	    System.out.println("PREDICATE");
	    if ((newpredicate = (Property) h.get(predicate)) == null) {
		newpredicate = copyPredicate(predicate, out);
		h.put(predicate,newpredicate);
	    }

	    //	    System.out.println("OBJECT");
	    if ((newobject = (RDFNode) h.get(object)) == null) {
		newobject = copyObject(object, out);
		h.put(object,newobject);
	    }
	    //    System.out.println("-------------------------------------");
	    out.add(new StatementImpl(newsubject, newpredicate, newobject));
	}
	return out;
    }

    private static Resource copySubject(Resource subject, Model out)
	throws RDFException
    {
	if (subject instanceof Property) {
	    return (Resource) copyPredicate((Property) subject, out);
	} else if (subject.isAnon() || 
		   subject.getNameSpace().equals(anonstring)) {
	    return new ResourceImpl(out);
	} else {
	    return  new ResourceImpl(subject.getNameSpace(),
				     subject.getLocalName(),
				     out);
	}
    }

    private static Property copyPredicate(Property predicate, Model out)
	throws RDFException
    {
	if (predicate.getOrdinal() == 0) {
	    return new  PropertyImpl(predicate.getNameSpace(),
				     predicate.getLocalName(),
				     out);
	} else {
	    return new PropertyImpl(predicate.getNameSpace(),
				    predicate.getLocalName(),
				    predicate.getOrdinal(),
				    out);
	}
    }

    private static RDFNode copyObject(RDFNode object, Model out)
	throws RDFException
    {
	Resource  objectResource;
	if (object instanceof Resource) {
	    // Object is really a resource
	    return (RDFNode) copySubject((Resource) object, out);
	} else {
	    // why doesn't "else if (object instanceof Literal)" work??
	    // object is a literal
	    return new LiteralImpl(object.toString());
	} 
    }
}
