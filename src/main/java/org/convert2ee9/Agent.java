/*
 *  JBoss, Home of Professional Open Source.
 *  Copyright 2020, Red Hat, Inc., and individual contributors
 *  as indicated by the @author tags. See the copyright.txt file in the
 *  distribution for a full listing of individual contributors.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this software; if not, write to the Free
 *  Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.convert2ee9;

import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

import net.bytebuddy.agent.builder.AgentBuilder;

/**
 * Agent
 *
 * @author Scott Marlow
 */
public class Agent  {

    // TODO: do we need just a single instance or do we need per classloader instance?  
    //       I think that ByteBuddy caches information for each classloader, which should be cleared at undeploy time.
    //       I think that we hit an issue with Hibernate ORM not clearing some ByteBuddy memory. 
    static private Agent platformLevelinstance = new Agent();
    
    static {
        System.out.println("convert2ee9 agent: platformLevelinstance = " + platformLevelinstance);
        System.out.println("convert2ee9 agent: platformLevelinstance.classFileTransformer = " + platformLevelinstance.classFileTransformer);
    }
    
    private ClassFileTransformer classFileTransformer;
     
    public Agent() {
        // based on twitter.com/rafaelcodes/status/1125032183167688706
        classFileTransformer = 
        new AgentBuilder.Default()
                .type(nameStartsWith("javax."))
                .transform((b, t, cl, m) -> b
                        .name("jakarta." + t
                                .getName().substring(6)))
                .installOnByteBuddyAgent();
    }
}
