/*
 * Copyright 2020 Red Hat, Inc, and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
