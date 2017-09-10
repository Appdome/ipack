/*
 * Copyright (c) 2011, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.oracle.ipack.resources;

import com.oracle.ipack.resources.ResourceRules.Exclude;
import com.oracle.ipack.util.Base64;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class CodeResources {
    private final ResourceRules resourceRules;
    private final List<HashedResource> hashedResources;

    public CodeResources(final ResourceRules resourceRules) {
        this.resourceRules = resourceRules;
        this.hashedResources = new ArrayList<HashedResource>();
    }

    public void addHashedResource(
            final String resourceName,
            final byte[] resourceHash,
            final byte[] resource256Hash) {
        hashedResources.add(
                new HashedResource(resourceName,
                                   Base64.byteArrayToBase64(resourceHash),
                                   Base64.byteArrayToBase64(resource256Hash)));
    }

    public void write(final OutputStream os) throws IOException {
        final PrintWriter pw =
                new PrintWriter(
                    new BufferedWriter(
                        new OutputStreamWriter(os, "UTF-8")));

        pw.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                      + "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""
                      + " \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                      + "<plist version=\"1.0\">\n"
                      + "<dict>\n"
                      + "\t<key>files</key>\n"
                      + "\t<dict>\n");

        for (final HashedResource hashedResource: hashedResources) {
            appendResource(pw, hashedResource, false);
        }

        pw.append("\t</dict>\n"
                      + "\t<key>files2</key>\n"
                      + "\t<dict>\n");

        for (final HashedResource hashedResource: hashedResources) {
            if(hashedResource.getName().equals("Info.plist") || hashedResource.getName().equals("PkgInfo")) {
                continue;
            }
            appendResource(pw, hashedResource, true);
        }

        pw.append("\t</dict>\n"
                + "\t<key>rules</key>\n"
                + "\t<dict>\n"
                + "\t\t<key>^</key>\n"
                + "\t\t<true/>\n"
                + "\t\t<key>^.*\\.lproj/</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>optional</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>1000</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^.*\\.lproj/locversion.plist$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>omit</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>1100</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^version.plist$</key>\n"
                + "\t\t<true/>\n");
        if (resourceRules.getIsResourceRulesPlist()) {
            pw.append("\t\t<key>^ResourceRules.plist$</key>\n"
                    + "\t\t<dict>\n"
                    + "\t\t\t<key>omit</key>\n"
                    + "\t\t\t<true/>\n"
                    + "\t\t\t<key>weight</key>\n"
                    + "\t\t\t<real>100</real>\n"
                    + "\t\t</dict>\n");
        }
        pw.append("\t</dict>\n"
                + "\t<key>rules2</key>\n"
                + "\t<dict>\n"
                + "\t\t<key>.*\\.dSYM($|/)</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>11</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>20</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^(.*/)?\\.DS_Store$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>omit</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>2000</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>nested</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>10</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^.*</key>\n"
                + "\t\t<true/>\n"
                + "\t\t<key>^.*\\.lproj/</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>optional</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>1000</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^.*\\.lproj/locversion.plist$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>omit</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>1100</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^Info\\.plist$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>omit</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>20</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^PkgInfo$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>omit</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>20</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^[^/]+$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>nested</key>\n"
                + "\t\t\t<true/>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>10</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^embedded\\.provisionprofile$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>20</real>\n"
                + "\t\t</dict>\n"
                + "\t\t<key>^version\\.plist$</key>\n"
                + "\t\t<dict>\n"
                + "\t\t\t<key>weight</key>\n"
                + "\t\t\t<real>20</real>\n"
                + "\t\t</dict>\n");
        if (resourceRules.getIsResourceRulesPlist()) {
            pw.append("\t\t<key>^ResourceRules.plist$</key>\n"
                    + "\t\t<dict>\n"
                    + "\t\t\t<key>omit</key>\n"
                    + "\t\t\t<true/>\n"
                    + "\t\t\t<key>weight</key>\n"
                    + "\t\t\t<real>100</real>\n"
                    + "\t\t</dict>\n");
        }
        pw.append("\t</dict>\n"
                + "</dict>\n"
                + "</plist>\n");
        pw.flush();
    }

    private static void appendResource(final PrintWriter pw,
                                       final HashedResource hashedResource,
                                       final Boolean isFiles2) {
        //http://stackoverflow.com/a/32663908
        pw.append("\t\t<key>").append(xmlEscapeString(Normalizer.normalize(hashedResource.getName(), Normalizer.Form.NFD))).append("</key>\n");
        Pattern p = Pattern.compile("\\.nib$|\\/Info[^/]*\\.plist$");
        Matcher m = p.matcher(hashedResource.getName());
        Boolean shouldAddDict = isFiles2 || m.find();
        if(shouldAddDict) {
            pw.append("\t\t<dict>\n\t\t\t<key>hash</key>\n\t");
        }
        pw.append("\t\t<data>\n");
        if(shouldAddDict) {
            pw.append("\t");
        }
        pw.append("\t\t").append(hashedResource.getHash()).append('\n');
        if(shouldAddDict) {
            pw.append("\t");
        }
        pw.append("\t\t</data>\n");

        if(isFiles2) {
            pw.append("\t\t\t<key>hash2</key>\n\t\t\t<data>\n\t\t\t");
            pw.append(hashedResource.get256Hash()).append("\n\t\t\t</data>\n");
        }
        p = Pattern.compile("\\.png$");
        m = p.matcher(hashedResource.getName());
        Boolean isPng = m.find();
        p = Pattern.compile("Icon.*\\.png$|LaunchImage.*\\.png$");
        m = p.matcher(hashedResource.getName());
        Boolean isExcludedPng = m.find();
        p = Pattern.compile("^Assets.car$|^archived-expanded-entitlements.xcent$|^embedded.mobileprovision$|^entitlements.plist$");
        m = p.matcher(hashedResource.getName());
        Boolean otherExclusions = m.find();
        if(shouldAddDict) {
            if ((!isFiles2 && !isPng) || (isFiles2 && !otherExclusions && !isExcludedPng)) {
                pw.append("\t\t\t<key>optional</key>\n\t\t\t<true/>\n");
            }
        }
        if(shouldAddDict) {
            pw.append("\t\t</dict>\n");
        }
    }

    private static void appendExclude(final PrintWriter pw,
                                      final Exclude exclude) {
        pw.append("\t\t<key>").append(exclude.getName()).append("</key>\n")
          .append("\t\t<dict>\n")
          .append("\t\t\t<key>omit</key>\n")
          .append("\t\t\t<true/>\n")
          .append("\t\t\t<key>weight</key>\n")
          .append("\t\t\t<real>");
        pw.print(exclude.getWeight());
        pw.append("</real>\n")
          .append("\t\t</dict>\n");
    }

    private static final class HashedResource {
        private final String name;
        private final String hash;
        private final String hash256;

        public HashedResource(final String name, final String hash, final String hash256) {
            this.name = name;
            this.hash = hash;
            this.hash256 = hash256;
        }

        public String getName() {
            return name;
        }

        public String getHash() {
            return hash;
        }

        public String get256Hash() {
            return hash256;
        }
    }
    
    private static String xmlEscapeString(String t) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < t.length(); i++){
        char c = t.charAt(i);
        switch(c){
            case '<': sb.append("&lt;"); break;
            case '>': sb.append("&gt;"); break;
            case '\"': sb.append("&quot;"); break;
            case '&': sb.append("&amp;"); break;
            case '\'': sb.append("&apos;"); break;
            default:
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
