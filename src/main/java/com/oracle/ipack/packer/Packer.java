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

import com.oracle.ipack.signer.Signer;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class Packer {
    private final ZipOutputStream zipStream;
    private final Signer signer;
    private Boolean inPlace;

    public Packer(final File destFile,
                  final Signer signer,
                  final Boolean inPlace) throws FileNotFoundException {
        this.inPlace = inPlace;
        if (inPlace) { //In codesign.py this is what we use
            this.zipStream = new ZipOutputStream(
                                 new DataOutputStream(
                                     new ByteArrayOutputStream(128*1024*1024-1))); //Avoid java bug https://bugs.openjdk.java.net/browse/JDK-8055949 by being able to get to max buffer size of MAX_INT-16
            zipStream.setLevel(Deflater.NO_COMPRESSION);
        } else {
            this.zipStream = new ZipOutputStream(
                                 new BufferedOutputStream(
                                     new FileOutputStream(destFile)));
        }
        this.signer = signer;
    }

    public void storeApplication(
            final File baseDir,
            final String appPath,
            final String appName,
            final String appIdentifier,
            final String teamIdentifier,
            final String entitlements,
            final String resourcesHash,
            final String infoPlistHash,
            final String resources256Hash,
            final String infoPlist256Hash,
            final Boolean isBundle) throws IOException {
        final String normalizedAppPath = normalizePath(appPath);

        if (!normalizedAppPath.isEmpty()) {
            storeDirEntry(normalizedAppPath);
        }

        final ResourcePacker resourcePacker =
                new ResourcePacker(zipStream, baseDir, normalizedAppPath,
                                   appName, resourcesHash, infoPlistHash, resources256Hash, infoPlist256Hash, isBundle, inPlace);
        resourcePacker.execute();

        final ExecutablePacker executablePacker =
                new ExecutablePacker(zipStream, baseDir, normalizedAppPath,
                                     appName,
                                     appIdentifier,
                                     teamIdentifier,
                                     entitlements,
                                     inPlace,
                                     signer);

        executablePacker.setCodeResourcesHash(
                resourcePacker.getCodeResourcesHash());
        executablePacker.setInfoPlistHash(
                resourcePacker.getInfoPlistHash());
        executablePacker.setCodeResources256Hash(
                resourcePacker.getCodeResources256Hash());
        executablePacker.setInfoPlist256Hash(
                resourcePacker.getInfoPlist256Hash());
        executablePacker.execute();
    }

    public void close() {
        try {
            zipStream.close();
        } catch (final IOException e) {
            // ignore
        }
    }

    private void storeDirEntry(final String entryName) throws IOException {
        // TODO: intermediate dirs
        zipStream.putNextEntry(new ZipEntry(entryName));
        zipStream.closeEntry();
    }

    private static String normalizePath(final String path) {
        if (path.isEmpty() || path.endsWith("/")) {
            return path;
        }

        return path + '/';
    }
}
