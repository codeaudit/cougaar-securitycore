package org.cougaar.core.security.policy.enforcers.util;

import java.util.*;

public class UserDatabase
{
    private static HashMap userToRoles = new HashMap();
    private static int     userCounter = 0;

    public static String anybody()   // need to think about this
    {                                // for now semantic matcher always says match
	return "Everybody";          // maybe need NO_INSTANCE_FOUND???
    }

    public static String login(Set roles)
    {
	String user = "User" + (userCounter++);
	userToRoles.put(user, roles);
	return user;
    }

    public static boolean logout(String user)
    {
	if (userToRoles.remove(user) != null) {
	    return true;
	} else {
	    return false;
	}
    }

    public static Set getRoles(String user)
    {
	Set roles = (Set) userToRoles.get(user);
	if (roles == null) {
	    return new HashSet();
	} else {
	    return roles;
	}
    }
}
