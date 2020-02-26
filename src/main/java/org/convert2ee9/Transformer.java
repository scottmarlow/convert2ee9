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

import static org.objectweb.asm.Opcodes.ACC_PUBLIC;
import static org.objectweb.asm.Opcodes.ACC_STATIC;


import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Transformer
 * <p>
 * Map javax.* classes to their jakarta.* equivalent as outlined on
 * https://github.com/eclipse-ee4j/jakartaee-platform/blob/master/namespace/mappings.adoc
 *
 * @author Scott Marlow
 */
public class Transformer implements ClassFileTransformer {

    private static final boolean useASM7 = getMajorJavaVersion() >= 11;
    private static final String markerAlreadyTransformed = "$_org_convert2ee9_Transformer_transformed_$";

    private boolean classTransformed;
    private boolean alreadyTransformed;

    @Override
    public byte[] transform(final ClassLoader loader, final String className, final Class<?> classBeingRedefined, final ProtectionDomain protectionDomain, final byte[] classfileBuffer) throws IllegalClassFormatException {
        final ClassReader classReader = new ClassReader(classfileBuffer);

        final ClassWriter classWriter = new ClassWriter(classReader, 0) {

            // Pass the classloader in so org.objectweb.asm.ClassWriter.getCommonSuperClass() uses the app classloader
            // instead of ASM classloader, for loading super classes.
            @Override
            protected ClassLoader getClassLoader() {
                return loader;
            }

        };
        classReader.accept(new ClassVisitor(useASM7 ? Opcodes.ASM7 : Opcodes.ASM6, classWriter) {

            // clear transformed state at start of each class visit
            @Override
            public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                // clear per class state
                clearTransformationState();
            }

            // check if class has already been transformed
            @Override
            public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
                // check if class has already been modified
                if (markerAlreadyTransformed.equals(name) &&
                        desc.equals("Z")) {
                    setAlreadyTransformed(true);
                }
                return super.visitField(access, name, desc, signature, value);
            }

            // mark class as transformed (only if class transformations were made)
            @Override
            public void visitEnd() {
                if (transformationsMade()) {
                    cv.visitField(ACC_PUBLIC + ACC_STATIC, markerAlreadyTransformed, "Z", null, null).visitEnd();
                }
                super.visitEnd();
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {

                final String descOrig = desc;

                desc = replaceJavaXwithJakarta(desc);
                if (!descOrig.equals(desc)) {  // if we are changing
                    // mark the class as transformed
                    setClassTransformed(true);
                }
                MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
                String className1 = className;

                return new MethodVisitor(Opcodes.ASM6, mv) {
                    private final String className = className1;

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                        
                        final String descOrig = desc;
            
                        if (methodCall(opcode)) {
                            desc = replaceJavaXwithJakarta(desc);
                            if (!descOrig.equals(desc)) {  // if we are changing
                                // mark the class as transformed
                                setClassTransformed(true);
                            }
                        } 
                        mv.visitMethodInsn(opcode, owner, name, desc, itf);
                    }

                    private boolean methodCall(int opcode) {
                        return opcode == Opcodes.INVOKESPECIAL ||
                                opcode == Opcodes.INVOKEVIRTUAL ||
                                opcode == Opcodes.INVOKEINTERFACE ||
                                opcode == Opcodes.INVOKESTATIC;
                    }

                    @Override
                    public void visitFieldInsn(int opcode, String owner, String name, String desc) {
                        // check for app references to a javax field
                        if (opcode == Opcodes.GETSTATIC) {
                            final String descOrig = desc;
                            desc = replaceJavaXwithJakarta(desc);
                            if (!descOrig.equals(desc)) {  // if we are changing
                                // mark the class as transformed
                                setClassTransformed(true);
                            }
                        } 
                        mv.visitFieldInsn(opcode, owner, name, desc);
                    }
                };
            }
        }, 0);
        if (!transformationsMade()) {
            // no change was made, indicate so by returning null
            return null;
        }

        byte[] result = classWriter.toByteArray();
        return result;
    }

    private static String replaceJavaXwithJakarta(String desc) {
        
        if (desc.contains("javax/transaction/xa")) {
            // do not transform references to the JDK javax.transaction.xa classes
            return desc;
        }
        return desc.
                replace("javax/annotation/security","jakarta/annotation/security").
                replace("javax/annotation/sql","jakarta/annotation/sql").
                replace("javax/batch","jakarta/batch").
                replace("javax/decorator","jakarta/decorator").
                replace("javax/ejb","jakarta/ejb").
                replace("javax/el","jakarta/el").
                replace("javax/enterprise","jakarta/enterprise").
                replace("javax/faces","jakarta/faces").
                replace("javax/inject","jakarta/inject").
                replace("javax/interceptor","jakarta/interceptor").
                replace("javax/jms","jakarta/jms").
                replace("javax/json","jakarta/json").
                replace("javax/mail","jakarta/mail").
                replace("javax/management/j2ee","jakarta/management/j2ee").
                replace("javax/persistence","jakarta/persistence").
                replace("javax/resource","jakarta/resource").
                replace("javax/security/auth","jakarta/security/auth").
                replace("javax/security/enterprise","jakarta/security/enterprise").
                replace("javax/security/jacc","jakarta/security/jacc").
                replace("javax/servlet","jakarta/servlet").
                replace("javax/transaction","jakarta/transaction").
                replace("javax/validation","jakarta/validation").
                replace("javax/websocket","jakarta/websocket").
                replace("javax/ws/rs","jakarta/ws/rs");
    }

    private static int getMajorJavaVersion() {
        int major = 8;
        String version = System.getProperty("java.specification.version", null);
        if (version != null) {
            Matcher matcher = Pattern.compile("^(?:1\\.)?(\\d+)$").matcher(version);
            if (matcher.find()) {
                major = Integer.valueOf(matcher.group(1));
            }
        }
        return major;
    }

    public void setClassTransformed(boolean classTransformed) {
        this.classTransformed = classTransformed;
    }

    public void setAlreadyTransformed(boolean alreadyTransformed) {
        this.alreadyTransformed = alreadyTransformed;
    }

    public boolean transformationsMade() {
        return !alreadyTransformed && classTransformed;
    }

    public void clearTransformationState() {
        alreadyTransformed = classTransformed = false;
    }
    
}
