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


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.TypePath;

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

    public byte[] transform(final ClassReader classReader) {
        
        final ClassWriter classWriter = new ClassWriter(classReader, 0);
        final String className = classReader.getClassName();
 
        classReader.accept(new ClassVisitor(useASM7 ? Opcodes.ASM7 : Opcodes.ASM6, classWriter) {
            

            // clear transformed state at start of each class visit
            @Override
            public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                // clear per class state
                clearTransformationState();
                System.out.println("transforming " + className);
                super.visit(version, access, name, signature, superName, interfaces);
            }

            // check if class has already been transformed
            @Override
            public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {

                // check if class has already been modified
                if (markerAlreadyTransformed.equals(name) &&
                        desc.equals("Z")) {
                    System.out.println(className + " has already been transformed.");
                    setAlreadyTransformed(true);
                } else {
                    final String descOrig = desc;
                    desc = replaceJavaXwithJakarta(desc);
                    if (!descOrig.equals(desc)) {  // if we are changing
                        // mark the class as transformed
                        setClassTransformed(true);
                    }
                }
                FieldVisitor fv = super.visitField(access, name, desc, signature, value);
                return new FieldVisitor(api, fv) {
                    @Override
                    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                        final String descOrig = descriptor;
                        descriptor = replaceJavaXwithJakarta(descriptor);
                        if (!descOrig.equals(descriptor)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                            }
                        return fv.visitAnnotation(descriptor, visible);
                    }

                    @Override
                    public AnnotationVisitor visitTypeAnnotation(int typeRef, TypePath typePath, String descriptor, boolean visible) {
                        final String descOrig = descriptor;
                        descriptor = replaceJavaXwithJakarta(descriptor);
                        if (!descOrig.equals(descriptor)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                            }
                        return fv.visitTypeAnnotation(typeRef, typePath, descriptor, visible);
                    }
                };
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

                final String descOrig2 = desc;

                desc = replaceJavaXwithJakarta(desc);
                if (!descOrig2.equals(desc)) {  // if we are changing
                    // mark the class as transformed
                    setClassTransformed(true);
                }
                return new MethodVisitor(Opcodes.ASM6, 
                        super.visitMethod(access, name, desc, signature, exceptions)) {

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
                        
                        final String descOrig = desc;
                        desc = replaceJavaXwithJakarta(desc);
                        final String ownerOrig = owner;
                        owner = replaceJavaXwithJakarta(owner);
                        if (!descOrig.equals(desc) | !ownerOrig.equals(owner)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                        }
                        mv.visitMethodInsn(opcode, owner, name, desc, itf);
                    }

                    @Override
                    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
                        final String descOrig = descriptor;
            
                        descriptor = replaceJavaXwithJakarta(descriptor);
                        if (!descOrig.equals(descriptor)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                        }
                        return mv.visitAnnotation(descriptor, visible);
                    }

                    @Override
                    public void visitLdcInsn(final Object value) {
                        if (value instanceof Type) {
                            Type type = (Type)value;
                            String descOrig = type.getDescriptor();
                            String desc = replaceDottedJavaXwithJakarta(replaceJavaXwithJakarta(descOrig));
                            if (!descOrig.equals(desc)) { // if we are changing
                                // mark the class as transformed
                                setClassTransformed(true);
                                mv.visitLdcInsn(Type.getType(desc));
                                return;
                            }
                        }
                        
                        if (value instanceof String) {
                            final String typeOrig = (String) value;
                            String replacement = replaceDottedJavaXwithJakarta((String)value);
                            replacement = replaceJavaXwithJakarta(replacement);
                            if (!typeOrig.equals(replacement)) {  // if we are changing
                                // mark the class as transformed
                                setClassTransformed(true);
                                mv.visitLdcInsn(replacement);
                                return;
                            }
                        }
                        mv.visitLdcInsn(value);
                    }
                    
                    @Override
                    public void visitLocalVariable(
                        final String name,
                        final String descriptor,
                        final String signature,
                        final Label start,
                        final Label end,
                        final int index) {
                        
                        final String descOrig = descriptor;
                        final String replacement = replaceJavaXwithJakarta(descriptor);
                        if (!descOrig.equals(replacement)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                        }
                        mv.visitLocalVariable(name, replacement, signature, start, end, index);
                    }

                    @Override
                    public void visitFieldInsn(int opcode, String owner, String name, String desc) {
                        final String descOrig = desc;
                        desc = replaceJavaXwithJakarta(desc);
                        final String ownerOrig = owner;
                        owner = replaceJavaXwithJakarta(owner);
                        if (!descOrig.equals(desc) | !ownerOrig.equals(owner)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                        }
                        mv.visitFieldInsn(opcode, owner, name, desc);
                    }
                    
                    @Override
                    public void visitTypeInsn(final int opcode, final String type) {
                        final String typeOrig = type;
            
                        final String replacement = replaceJavaXwithJakarta(type);
                        if (!typeOrig.equals(replacement)) {  // if we are changing
                            // mark the class as transformed
                            setClassTransformed(true);
                        }
                        mv.visitTypeInsn(opcode, replacement);
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
    
    @Override
    public byte[] transform(final ClassLoader loader, final String className, final Class<?> classBeingRedefined, final ProtectionDomain protectionDomain, final byte[] classfileBuffer) throws IllegalClassFormatException {
        final ClassReader classReader = new ClassReader(classfileBuffer);
        return transform(classReader);
    }

    private static String replaceJavaXwithJakarta(String desc) {
        // note that we will ignore JDK javax.transaction.xa classes
        String result = desc.
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
                // only need to match with first letter of javax.transaction level classes
                replace("javax/transaction/H","jakarta/transaction/H").
                replace("javax/transaction/I","jakarta/transaction/I").
                replace("javax/transaction/N","jakarta/transaction/N").
                replace("javax/transaction/R","jakarta/transaction/R").
                replace("javax/transaction/S","jakarta/transaction/S").
                replace("javax/transaction/T","jakarta/transaction/T").
                replace("javax/transaction/U","jakarta/transaction/U").
                replace("javax/validation","jakarta/validation").
                replace("javax/websocket","jakarta/websocket").
                replace("javax/ws/rs","jakarta/ws/rs");
        
        return result;
    }

    private static String replaceDottedJavaXwithJakarta(String desc) {
        // note that we will ignore JDK javax.transaction.xa classes
        String result = desc.
                replace("javax.annotation.security","jakarta.annotation.security").
                replace("javax.annotation.sql","jakarta.annotation.sql").
                replace("javax.batch","jakarta.batch").
                replace("javax.decorator","jakarta.decorator").
                replace("javax.ejb","jakarta.ejb").
                replace("javax.el","jakarta.el").
                replace("javax.enterprise","jakarta.enterprise").
                replace("javax.faces","jakarta.faces").
                replace("javax.inject","jakarta.inject").
                replace("javax.interceptor","jakarta.interceptor").
                replace("javax.jms","jakarta.jms").
                replace("javax.json","jakarta.json").
                replace("javax.mail","jakarta.mail").
                replace("javax.management.j2ee","jakarta.management.j2ee").
                replace("javax.persistence","jakarta.persistence").
                replace("javax.resource","jakarta.resource").
                replace("javax.security.auth","jakarta.security.auth").
                replace("javax.security.enterprise","jakarta.security.enterprise").
                replace("javax.security.jacc","jakarta.security.jacc").
                replace("javax.servlet","jakarta.servlet").
                // only need to match with first letter of javax.transaction level classes
                replace("javax.transaction.H","jakarta.transaction.H").
                replace("javax.transaction.I","jakarta.transaction.I").
                replace("javax.transaction.N","jakarta.transaction.N").
                replace("javax.transaction.R","jakarta.transaction.R").
                replace("javax.transaction.S","jakarta.transaction.S").
                replace("javax.transaction.T","jakarta.transaction.T").
                replace("javax.transaction.U","jakarta.transaction.U").
                replace("javax.validation","jakarta.validation").
                replace("javax.websocket","jakarta.websocket").
                replace("javax.ws.rs","jakarta.ws.rs");
        
        return result;
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
    
    public static void main(final String... args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: " + Transformer.class + " sourceClassFile targetClassFile");
            return;
        }
        // configure transformer
        String to = null;
        Transformer t = new Transformer();
        // get original class content
        final ByteArrayOutputStream targetBAOS = new ByteArrayOutputStream();
        final Path source = Paths.get(args[0]);
        InputStream inputStream = Files.newInputStream(source);
        try {
            ClassReader classReader = new ClassReader(inputStream);
            final byte[] targetBytes = t.transform(classReader);
            // write modified class content
            final ByteArrayInputStream sourceBAIS = new ByteArrayInputStream(targetBytes);
            final Path target = Paths.get(args[1]);
            Files.copy(sourceBAIS, target);
        } finally {
            inputStream.close();    
        }
    }
}
