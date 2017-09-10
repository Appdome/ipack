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

package com.oracle.ipack.packer;

import com.oracle.ipack.Pair;
import com.oracle.ipack.resources.CodeResources;
import com.oracle.ipack.resources.ResourceRules;
import com.oracle.ipack.util.DataCopier;
import com.oracle.ipack.util.HashingOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.xml.bind.DatatypeConverter;

final class ResourcePacker {
    private final ZipOutputStream zipStream;
    private final File baseDir;
    private final String appPath;
    private final String resourcesHashStr;
    private final String infoPlistHashStr;
    private final String resources256HashStr;
    private final String infoPlist256HashStr;

    private final DataCopier dataCopier;
    private final ResourceRules resourceRules;
    private final HashingOutputStream dataStream;

    private final Boolean isBundle;
    private final Boolean inPlace;
    private byte[] codeResourcesHash;
    private byte[] infoPlistHash;
    private byte[] codeResources256Hash;
    private byte[] infoPlist256Hash;

    ResourcePacker(final ZipOutputStream zipStream,
                   final File baseDir,
                   final String appPath,
                   final String appName,
                   final String resourcesHashStr,
                   final String infoPlistHashStr,
                   final String resources256HashStr,
                   final String infoPlist256HashStr,
                   final Boolean isBundle,
                   final Boolean inPlace) {
        this.zipStream = zipStream;
        this.baseDir = baseDir;
        this.appPath = appPath;
        this.resourcesHashStr = resourcesHashStr;
        this.infoPlistHashStr = infoPlistHashStr;
        this.resources256HashStr = resources256HashStr;
        this.infoPlist256HashStr = infoPlist256HashStr;
        this.isBundle = isBundle;
        this.inPlace = inPlace;

        dataCopier = new DataCopier();
        dataStream = new HashingOutputStream(zipStream);

        infoPlistHash = new byte[20];
        infoPlist256Hash = new byte[32];

        resourceRules = new ResourceRules();
        resourceRules.addExclude(appName, -1);
        resourceRules.addExclude("_CodeSignature", -1);
        resourceRules.addExclude("CodeResources", -1);
        resourceRules.addExclude("ResourceRules.plist", 100);
    }

    void execute() throws IOException {
        final CodeResources codeResources = new CodeResources(resourceRules);

        if (!isBundle) {
            codeResourcesHash = new byte[20];
            codeResources256Hash = new byte[32];
        } else if (resourcesHashStr != null) {
            codeResourcesHash = DatatypeConverter.parseHexBinary(resourcesHashStr);
            codeResources256Hash = DatatypeConverter.parseHexBinary(resources256HashStr);
            if (infoPlistHashStr != null) {
                infoPlistHash = DatatypeConverter.parseHexBinary(infoPlistHashStr);
            }
            if (infoPlist256HashStr != null) {
                infoPlist256Hash = DatatypeConverter.parseHexBinary(infoPlist256HashStr);
            }
        } else {
            storeResourceFiles(codeResources);
            Pair<byte[], byte[]> codeResourcesHashPair = storeCodeResources(codeResources);
            codeResourcesHash = codeResourcesHashPair.first;
            codeResources256Hash = codeResourcesHashPair.second;
        }
        //This should be the only output from the program ever, it's used by codesign.py and any other output will cause codesign.py to stop working
        System.out.println(DatatypeConverter.printHexBinary(codeResourcesHash));
        System.out.println(DatatypeConverter.printHexBinary(codeResources256Hash));
        System.out.println(DatatypeConverter.printHexBinary(infoPlistHash));
        System.out.println(DatatypeConverter.printHexBinary(infoPlist256Hash));
    }

    byte[] getCodeResourcesHash() {
        return codeResourcesHash;
    }

    byte[] getInfoPlistHash() {
        return infoPlistHash;
    }

    byte[] getCodeResources256Hash() {
        return codeResources256Hash;
    }

    byte[] getInfoPlist256Hash() {
        return infoPlist256Hash;
    }

    private void storeResourceFiles(final CodeResources codeResources)
            throws IOException {
        final List<String> resources =
                resourceRules.collectResources(
                        new File(baseDir, appPath));

        for (final String resourceName: resources) {
            final String fullResourceName =
                    appPath + resourceName;
            if (resourceName.endsWith("/")) {
                storeDirEntry(fullResourceName);
                continue;
            }

            final Pair<byte[], byte[]> resourceHashPair = storeFileEntry(fullResourceName, new File(baseDir, fullResourceName));
            final byte[] resourceHash = resourceHashPair.first;
            final byte[] resourceHash256 = resourceHashPair.second;
            codeResources.addHashedResource(resourceName, resourceHash, resourceHash256);
        }
    }

    private Pair<byte[], byte[]> storeCodeResources(final CodeResources codeResources)
            throws IOException {
        storeDirEntry(appPath + "_CodeSignature/");

        final String codeResourcesName =
                appPath + "_CodeSignature/CodeResources";

        //System.out.println("Resource Adding " + codeResourcesName);
        zipStream.putNextEntry(new ZipEntry(codeResourcesName));
        try {
            codeResources.write(dataStream);
        } finally {
            dataStream.flush();
            zipStream.closeEntry();
        }
        if (inPlace) {
            (new File(baseDir, "_CodeSignature")).mkdirs();
            File codeResourcesFile = new File(baseDir, codeResourcesName);
            codeResourcesFile.createNewFile();
            FileOutputStream codeResourcesFileStream = new FileOutputStream(codeResourcesFile);
            codeResources.write(codeResourcesFileStream);
            codeResourcesFileStream.close();
        }

        return new Pair<byte[], byte[]>(dataStream.calculateHash(), dataStream.calculateHash(256));
    }

    private void storeDirEntry(final String entryName) throws IOException {
        zipStream.putNextEntry(new ZipEntry(entryName));
        zipStream.closeEntry();
    }

    private Pair<byte[], byte[]> storeFileEntry(final String entryName,
                                  final File file) throws IOException {
        //System.out.println("Adding " + entryName);
        zipStream.putNextEntry(new ZipEntry(entryName));
        try {
            dataCopier.copyFile(dataStream, file);
        } finally {
            dataStream.flush();
            zipStream.closeEntry();
        }

        byte[] hash = dataStream.calculateHash();
        byte[] hash256 = dataStream.calculateHash(256);
        if(isBundle && entryName.equals(appPath + "Info.plist")) {
            infoPlistHash = hash;
            infoPlist256Hash = hash256;
        }
        return new Pair<byte[], byte[]>(hash, hash256);
    }
}
