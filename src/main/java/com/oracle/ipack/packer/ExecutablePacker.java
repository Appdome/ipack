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
import com.oracle.ipack.blobs.Blob;
import com.oracle.ipack.blobs.VirtualBlob;
import com.oracle.ipack.blobs.WrapperBlob;
import com.oracle.ipack.macho.CodeSignatureCommand;
import com.oracle.ipack.macho.MachoCommand;
import com.oracle.ipack.macho.MachoHeader;
import com.oracle.ipack.macho.SegmentCommand;
import com.oracle.ipack.macho.SegmentCommand.Section;
import com.oracle.ipack.signature.CodeDirectoryBlob;
import com.oracle.ipack.signature.EmbeddedSignatureBlob;
import com.oracle.ipack.signature.EntitlementsBlob;
import com.oracle.ipack.signature.Requirement;
import com.oracle.ipack.signature.RequirementBlob;
import com.oracle.ipack.signature.RequirementsBlob;
import com.oracle.ipack.signer.Signer;
import com.oracle.ipack.util.DataCopier;
import com.oracle.ipack.util.HashingOutputStream;
import com.oracle.ipack.util.LsbDataInputStream;
import com.oracle.ipack.util.LsbDataOutputStream;
import com.oracle.ipack.util.NullOutputStream;
import com.oracle.ipack.util.PageHashingOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.bouncycastle.cms.CMSException;

final class ExecutablePacker {
    private static final int RESERVED_SIGNATURE_BLOB_SIZE = 9000;

    private final ZipOutputStream zipStream;
    private final File baseDir;
    private final String appPath;
    private final String appName;
    private final String appIdentifier;
    private final String teamIdentifier;
    private final Signer signer;
    private final String entitlements;
    private final Boolean inPlace;

    private byte[] codeResourcesHash;
    private byte[] infoPlistHash;
    private byte[] codeResources256Hash;
    private byte[] infoPlist256Hash;

    ExecutablePacker(final ZipOutputStream zipStream,
                     final File baseDir,
                     final String appPath,
                     final String appName,
                     final String appIdentifier,
                     final String teamIdentifier,
                     final String entitlements,
                     final Boolean inPlace,
                     final Signer signer) {
        this.zipStream = zipStream;
        this.baseDir = baseDir;
        this.appPath = appPath;
        this.appName = appName;
        this.appIdentifier = appIdentifier;
        this.teamIdentifier = teamIdentifier;
        this.entitlements = entitlements;
        this.inPlace = inPlace;
        this.signer = signer;
    }

    void setCodeResourcesHash(final byte[] codeResourcesHash) {
        this.codeResourcesHash = codeResourcesHash;
    }

    void setInfoPlistHash(final byte[] infoPlistHash) {
        this.infoPlistHash = infoPlistHash;
    }

    void setCodeResources256Hash(final byte[] codeResources256Hash) {
        this.codeResources256Hash = codeResources256Hash;
    }

    void setInfoPlist256Hash(final byte[] infoPlist256Hash) {
        this.infoPlist256Hash = infoPlist256Hash;
    }
    void execute() throws IOException {
        File execFile = new File(baseDir, appPath + appName);
        final InputStream execInputStream = new BufferedInputStream(new FileInputStream(execFile));
        try {
            final MachoHeader header =
                    MachoHeader.read(new LsbDataInputStream(execInputStream));
            final int oldHeaderSize = header.getSize();

            final SegmentCommand linkeditSegment =
                    header.findSegment("__LINKEDIT");
            if (linkeditSegment == null) {
                throw new IOException("Linkedit segment not found");
            }

            CodeSignatureCommand codeSignatureCommand =
                    (CodeSignatureCommand) header.findCommand(
                                               MachoCommand.LC_CODE_SIGNATURE);
            int originalCodeLimit = linkeditSegment.getFileOffset() + linkeditSegment.getFileSize();
            if (codeSignatureCommand == null) {
                // no previous signature in the executable
                codeSignatureCommand = new CodeSignatureCommand();
                codeSignatureCommand.setDataOffset((
                        linkeditSegment.getFileOffset()
                            + linkeditSegment.getFileSize() + 15) & ~15);
                header.addCommand(codeSignatureCommand);
            } else {
                originalCodeLimit = codeSignatureCommand.getDataOffset();
            }
            final int codeLimit = codeSignatureCommand.getDataOffset();

            final SegmentCommand textSegment = header.findSegment("__TEXT");
            if (textSegment != null) {
                final Section infoPlistSection = textSegment.findSection("__info_plist");
                if (infoPlistSection != null) {
                    final HashingOutputStream hashingStream = new HashingOutputStream(new NullOutputStream());
                    final DataOutputStream dataStream = new DataOutputStream(hashingStream);
                    try {
                        RandomAccessFile raf = new RandomAccessFile(new File(baseDir, appPath + appName), "r");
                        raf.seek(infoPlistSection.getOffset());
                        final byte[] embeddedInfoPlist = new byte[infoPlistSection.getSize()]; //In arm64 we would have to take size2 into account, we are assuming that the size is small enough to fit in size(1)
                        raf.read(embeddedInfoPlist, 0, infoPlistSection.getSize());
                        raf.close();
                        dataStream.write(embeddedInfoPlist, 0, infoPlistSection.getSize());
                    } finally {
                        dataStream.close();
                    }

                    final byte[] embeddedInfoPlistHash = hashingStream.calculateHash();
                    if (!Arrays.equals(infoPlistHash, embeddedInfoPlistHash) && !Arrays.equals(infoPlistHash, new byte[20])) {
                        throw new IOException("Plist file hash and embedded plist hash don't match");
                    }
                    infoPlistHash = embeddedInfoPlistHash;
                    
                    final byte[] embeddedInfoPlist256Hash = hashingStream.calculateHash(256);
                    if (!Arrays.equals(infoPlist256Hash, embeddedInfoPlist256Hash) && !Arrays.equals(infoPlist256Hash, new byte[32])) {
                        throw new IOException("Plist file SHA-256 hash and embedded plist SHA-256 hash don't match");
                    }
                    infoPlist256Hash = embeddedInfoPlist256Hash;
                }
            }

            final EntitlementsBlob embeddedEntitlementsBlob = new EntitlementsBlob(new File(entitlements));
            final EmbeddedSignatureBlob embeddedSignatureBlob =
                    createEmbeddedSignatureBlob(
                            appIdentifier,
                            teamIdentifier,
                            signer.getSubjectName(),
                            codeLimit,
                            embeddedEntitlementsBlob);
            // update the header with information about the new embedded
            // code signature
            final int reservedForEmbeddedSignature =
                    (embeddedSignatureBlob.getSize() + 15) & ~15;
            codeSignatureCommand.setDataSize(reservedForEmbeddedSignature);
            final int newLinkeditSize =
                    codeLimit - linkeditSegment.getFileOffset()
                              + reservedForEmbeddedSignature;
            linkeditSegment.setFileSize(newLinkeditSize);
            linkeditSegment.setVmSize((newLinkeditSize + 0x3fff) & ~0x3fff);
            final int newHeaderSize = header.getSize();

            final int firstSectionOffset = header.getFirstSectionFileOffset();
            if (newHeaderSize > firstSectionOffset) {
                throw new IOException("Patched header too long. newHeaderSize: " + newHeaderSize + " firstSectionOffset: " + firstSectionOffset);
            }

            // we assume that there is only padding between the header and the
            // first section, so we can skip some of it in the input stream
            long totalToSkip = newHeaderSize - oldHeaderSize;
            long totalSkipped = 0;
            long leftToSkip = totalToSkip;
            long skipped = 0;
            do {
                skipped = execInputStream.skip(leftToSkip);
                totalSkipped += skipped;
                leftToSkip -= skipped;
            } while(leftToSkip > 0 && skipped > 0);
            if (totalSkipped != totalToSkip) {
                throw new IOException("Couldn't skip " + totalToSkip + " bytes, only skipped " + totalSkipped + " bytes");
            }

            // start the executable zip entry
            final String entryName = appPath + appName;
            //System.out.println("Executable Adding " + entryName);
            zipStream.putNextEntry(new ZipEntry(entryName));
            PageHashingOutputStream hashingStream = null;
            File tempFile = null;
            FileOutputStream execOutputFileStream = null;
            if (inPlace) {
                tempFile = new File(baseDir, entryName + "_temp");
            }
            try {
                if (inPlace) {
                    execOutputFileStream = new FileOutputStream(tempFile);
                    hashingStream = new PageHashingOutputStream(execOutputFileStream);
                } else {
                    hashingStream = new PageHashingOutputStream(zipStream);
                }

                // store the patched header
                writeHeader(hashingStream, header);

                // copy the rest of the executable up to the codeLimit
                final DataCopier dataCopier = new DataCopier();
                // no need to use buffered stream, because the data is copied in
                // large chunks
                dataCopier.copyStream(hashingStream, execInputStream,
                                      codeLimit - newHeaderSize);
                hashingStream.write(new byte[(((originalCodeLimit + 15) & ~15) - originalCodeLimit)]); //Pad with zeros to the nearest 16

                // finalize the last page hash
                hashingStream.flush();
                hashingStream.commitPageHash();

                // update the code directory blobs with hashes
                final Pair<byte[], byte[]> requirementsBlobHashPair = calculateBlobHash(embeddedSignatureBlob.getRequirementsSubBlob());
                final byte[] requirementsBlobHash = requirementsBlobHashPair.first;
                final byte[] requirementsBlob256Hash = requirementsBlobHashPair.second;
                final Pair<byte[], byte[]>  entitlementsBlobHashPair = calculateBlobHash(embeddedSignatureBlob.getEntitlementsSubBlob());
                final byte[] entitlementsBlobHash = entitlementsBlobHashPair.first;
                final byte[] entitlementsBlob256Hash = entitlementsBlobHashPair.second;
                updateHashes(embeddedSignatureBlob.getCodeDirectorySubBlob(),
                             hashingStream.getPageHashes(),
                             infoPlistHash,
                             requirementsBlobHash,
                             codeResourcesHash,
                             entitlementsBlobHash);
                updateHashes(embeddedSignatureBlob.getCodeDirectory256SubBlob(),
                             hashingStream.getPageHashes(256),
                             infoPlist256Hash,
                             requirementsBlob256Hash,
                             codeResources256Hash,
                             entitlementsBlob256Hash);

                // sign the embedded signature blob
                signEmbeddedSignatureBlob(embeddedSignatureBlob, signer);

                // write the embedded signature blob and padding
                if (inPlace) {
                    writeEmbeddedSignatureBlob(execOutputFileStream, embeddedSignatureBlob, reservedForEmbeddedSignature);
                } else {
                    writeEmbeddedSignatureBlob(zipStream, embeddedSignatureBlob, reservedForEmbeddedSignature);
                }

                if (inPlace) {
                    hashingStream.close();
                    execInputStream.close();
                    Files.move(tempFile.toPath(), execFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            } catch  (final IOException e) {
                if (inPlace) {
                    Files.deleteIfExists(tempFile.toPath());
                }
                throw(e);
            } finally {
                if (inPlace) {
                    hashingStream.close();
                }
                zipStream.closeEntry();
            }
        } finally {
            execInputStream.close();
        }

    }

    private static EmbeddedSignatureBlob createEmbeddedSignatureBlob(
            final String appIdentifier,
            final String teamIdentifier,
            final String subjectName,
            final int codeLimit,
            final EntitlementsBlob entitlementsBlob) {
        final CodeDirectoryBlob codeDirectoryBlob =
                new CodeDirectoryBlob(appIdentifier, teamIdentifier, codeLimit);

        final CodeDirectoryBlob codeDirectory256Blob =
                new CodeDirectoryBlob(appIdentifier, teamIdentifier, codeLimit, 32, 2);

        final RequirementsBlob requirementsBlob = new RequirementsBlob(1);
        final RequirementBlob designatedRequirementBlob =
                new RequirementBlob(
                    Requirement.createDefault(appIdentifier, subjectName));
        requirementsBlob.setSubBlob(
                0, RequirementsBlob.KSEC_DESIGNATED_REQUIREMENT_TYPE,
                designatedRequirementBlob);

        final VirtualBlob reservedForSignatureBlob =
                new VirtualBlob(0, RESERVED_SIGNATURE_BLOB_SIZE - 8);

        final EmbeddedSignatureBlob embeddedSignatureBlob =
                new EmbeddedSignatureBlob();
        embeddedSignatureBlob.setCodeDirectorySubBlob(codeDirectoryBlob);
        embeddedSignatureBlob.setRequirementsSubBlob(requirementsBlob);
        embeddedSignatureBlob.setEntitlementsSubBlob(entitlementsBlob);
        embeddedSignatureBlob.setCodeDirectory256SubBlob(codeDirectory256Blob);
        embeddedSignatureBlob.setSignatureSubBlob(reservedForSignatureBlob);

        return embeddedSignatureBlob;
    }

    private static void signEmbeddedSignatureBlob(
            final EmbeddedSignatureBlob embeddedSignatureBlob,
            final Signer signer) throws IOException {
        final CodeDirectoryBlob codeDirectoryBlob =
                embeddedSignatureBlob.getCodeDirectorySubBlob();
        final ByteArrayOutputStream bos =
                new ByteArrayOutputStream(codeDirectoryBlob.getSize());
        final DataOutputStream os = new DataOutputStream(bos);
        try {
            codeDirectoryBlob.write(os);
        } finally {
            os.close();
        }

        final byte[] signature;
        try {
            signature = signer.sign(bos.toByteArray());
        } catch (final CMSException e) {
            throw new IOException("Failed to sign executable", e);
        }

        embeddedSignatureBlob.setSignatureSubBlob(
                new WrapperBlob(signature));
    }

    private static void writeHeader(
            final OutputStream dataStream,
            final MachoHeader header) throws IOException {
        final LsbDataOutputStream headerStream =
                new LsbDataOutputStream(new BufferedOutputStream(dataStream));

        try {
            header.write(headerStream);
        } finally {
            headerStream.flush();
        }
    }

    private static void writeEmbeddedSignatureBlob(
            final OutputStream dataStream,
            final EmbeddedSignatureBlob embeddedSignatureBlob,
            final int reservedForEmbeddedSignature) throws IOException {
        final int realEmbeddedSignatureSize =
                embeddedSignatureBlob.getSize();
        if (realEmbeddedSignatureSize > reservedForEmbeddedSignature) {
            throw new IOException("Embedded signature too large");
        }

        final DataOutputStream signatureStream =
                new DataOutputStream(new BufferedOutputStream(dataStream));
        try {
            embeddedSignatureBlob.write(signatureStream);

            // add padding
            for (int i = reservedForEmbeddedSignature
                             - realEmbeddedSignatureSize; i > 0; --i) {
                signatureStream.writeByte(0);
            }
        } finally {
            signatureStream.flush();
        }
    }

    private static void updateHashes(
            final CodeDirectoryBlob codeDirectoryBlob,
            final List<byte[]> pageHashes,
            final byte[] infoPlistHash,
            final byte[] requirementsHash,
            final byte[] codeResourcesHash,
            final byte[] entitlementsHash) {
        int i = 0;
        for (final byte[] pageHash: pageHashes) {
            codeDirectoryBlob.setCodeSlot(i++, pageHash);
        }

        if (entitlementsHash != null) {
            codeDirectoryBlob.setEntitlementsSlot(entitlementsHash);
        }

        if (infoPlistHash != null) {
            codeDirectoryBlob.setInfoPlistSlot(infoPlistHash);
        }

        if (requirementsHash != null) {
            codeDirectoryBlob.setRequirementsSlot(requirementsHash);
        }

        if (codeResourcesHash != null) {
            codeDirectoryBlob.setCodeResourcesSlot(codeResourcesHash);
        }
    }

    private static Pair<byte[], byte[]> calculateBlobHash(
            final Blob blob) {
        final HashingOutputStream hashingStream =
                new HashingOutputStream(new NullOutputStream());

        try {
            final DataOutputStream dataStream =
                    new DataOutputStream(hashingStream);
            try {
                blob.write(dataStream);
            } finally {
                dataStream.close();
            }

            return new Pair<byte[], byte[]>(hashingStream.calculateHash(), hashingStream.calculateHash(256));
        } catch (final IOException e) {
            // won't happen
            return new Pair<byte[], byte[]>(null, null);
        }
    }
}
