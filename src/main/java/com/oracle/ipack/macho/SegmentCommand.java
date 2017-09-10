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

package com.oracle.ipack.macho;

import com.oracle.ipack.util.Util;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.ArrayList;

public final class SegmentCommand extends MachoCommand {
    private final ArrayList<Section> sections;

    private String segmentName;
    private int vmAddress;
    private int vmAddress2;
    private int vmSize;
    private int vmSize2;
    private int fileOffset;
    private int fileOffset2;
    private int fileSize;
    private int fileSize2;
    private int maxVmProtection;
    private int initVmProtection;
    private int flags;
    private int id;

    public SegmentCommand(final int id) {
        this.id = id;
        sections = new ArrayList<Section>();
    }

    @Override
    public int getId() {
        return id;
    }

    public Section findSection(final String sectionName) {
        for (final Section section: sections) {
            if (sectionName.equals(section.getSectionName())) {
                return section;
            }
        }

        return null;
    }

    public String getSegmentName() {
        return segmentName;
    }

    public void setSegmentName(final String segmentName) {
        this.segmentName = segmentName;
    }

    public int getVmAddress() {
        return vmAddress;
    }

    public void setVmAddress(final int vmAddress) {
        this.vmAddress = vmAddress;
    }

    public int getVmAddress2() {
        return vmAddress2;
    }

    public void setVmAddress2(final int vmAddress2) {
        this.vmAddress2 = vmAddress2;
    }

    public int getVmSize() {
        return vmSize;
    }

    public void setVmSize(final int vmSize) {
        this.vmSize = vmSize;
    }

    public int getVmSize2() {
        return vmSize2;
    }

    public void setVmSize2(final int vmSize2) {
        this.vmSize2 = vmSize2;
    }

    public int getFileOffset() {
        return fileOffset;
    }

    public void setFileOffset(final int fileOffset) {
        this.fileOffset = fileOffset;
    }

    public int getFileOffset2() {
        return fileOffset2;
    }

    public void setFileOffset2(final int fileOffset2) {
        this.fileOffset2 = fileOffset2;
    }

    public int getFileSize() {
        return fileSize;
    }

    public void setFileSize(final int fileSize) {
        this.fileSize = fileSize;
    }

    public int getFileSize2() {
        return fileSize2;
    }

    public void setFileSize2(final int fileSize2) {
        this.fileSize2 = fileSize2;
    }

    public int getMaxVmProtection() {
        return maxVmProtection;
    }

    public void setMaxVmProtection(final int maxVmProtection) {
        this.maxVmProtection = maxVmProtection;
    }

    public int getInitVmProtection() {
        return initVmProtection;
    }

    public void setInitVmProtection(final int initVmProtection) {
        this.initVmProtection = initVmProtection;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(final int flags) {
        this.flags = flags;
    }

    public ArrayList<Section> getSections() {
        return sections;
    }

    @Override
    public String toString() {
        String ret = "SegmentCommand { segmentName: \"" + segmentName + "\"";
        ret += ", vmAddress: 0x" + Util.hex32(vmAddress);

        if(id == LC_SEGMENT_64) {
            ret += Util.hex32(vmAddress2);
        }
        ret += ", vmSize: 0x" + Util.hex32(vmSize);
        if(id == LC_SEGMENT_64) {
            ret += Util.hex32(vmSize2);
        }
        ret += ", fileOffset: 0x" + Util.hex32(fileOffset);
        if(id == LC_SEGMENT_64) {
            ret += Util.hex32(fileOffset2);
        }
        ret += ", fileSize: 0x" + Util.hex32(fileSize);
        if(id == LC_SEGMENT_64) {
            ret += Util.hex32(fileSize2);
        }
        ret += ", maxVmProtection: " + maxVmProtection
        + ", initVmProtection: " + initVmProtection
        + ", flags: 0x" + Util.hex32(flags)
        + ", sections: " + sections + " }";
        return ret;
    }

    @Override
    protected int getPayloadSize() {
        if(id == LC_SEGMENT) {
            return 16 + 4 * 8 + 68 * sections.size();
        } else if(id == LC_SEGMENT_64) {
            return 16 + 4 * 8 + 4 * 4 + 80 * sections.size();
        } else {
            System.out.println("Unknown id " + id);
            return 0;
        }
    }

    @Override
    protected void readPayload(final DataInput dataInput) throws IOException {
        segmentName = Util.readString(dataInput, 16).trim();
        vmAddress = dataInput.readInt();
        if(id == LC_SEGMENT_64) {
            vmAddress2 = dataInput.readInt();
        }
        vmSize = dataInput.readInt();
        if(id == LC_SEGMENT_64) {
            vmSize2 = dataInput.readInt();
        }
        fileOffset = dataInput.readInt();
        if(id == LC_SEGMENT_64) {
            fileOffset2 = dataInput.readInt();
        }
        fileSize = dataInput.readInt();
        if(id == LC_SEGMENT_64) {
            fileSize2 = dataInput.readInt();
        }
        maxVmProtection = dataInput.readInt();
        initVmProtection = dataInput.readInt();
        final int numberOfSections = dataInput.readInt();
        flags = dataInput.readInt();

        sections.clear();
        sections.ensureCapacity(numberOfSections);
        for (int i = 0; i < numberOfSections; ++i) {
            final Section section = new Section(id);
            section.readImpl(dataInput);
            sections.add(section);
        }
    }

    @Override
    protected void writePayload(final DataOutput dataOutput)
            throws IOException {
        Util.writeString(dataOutput, segmentName, 16, '\0');
        dataOutput.writeInt(vmAddress);
        if(id == LC_SEGMENT_64) {
            dataOutput.writeInt(vmAddress2);
        }
        dataOutput.writeInt(vmSize);
        if(id == LC_SEGMENT_64) {
            dataOutput.writeInt(vmSize2);
        }
        dataOutput.writeInt(fileOffset);
        if(id == LC_SEGMENT_64) {
            dataOutput.writeInt(fileOffset2);
        }
        dataOutput.writeInt(fileSize);
        if(id == LC_SEGMENT_64) {
            dataOutput.writeInt(fileSize2);
        }
        dataOutput.writeInt(maxVmProtection);
        dataOutput.writeInt(initVmProtection);
        dataOutput.writeInt(sections.size());
        dataOutput.writeInt(flags);

        for (final Section section: sections) {
            section.write(dataOutput);
        }
    }

    public static final class Section {
        private String sectionName;
        private String segmentName;
        private int address;
        private int address2;
        private int size;
        private int size2;
        private int offset;
        private int align;
        private int relocationOffset;
        private int numberOfRelocations;
        private int flags;
        private int reserved1;
        private int reserved2;
        private int reserved3;
        private int id;
        
        public Section(final int id) {
        	this.id = id;
        }

        public String getSectionName() {
            return sectionName;
        }

        public void setSectionName(final String sectionName) {
            this.sectionName = sectionName;
        }

        public String getSegmentName() {
            return segmentName;
        }

        public void setSegmentName(final String segmentName) {
            this.segmentName = segmentName;
        }

        public int getAddress() {
            return address;
        }

        public void setAddress(final int address) {
            this.address = address;
        }
        
        public int getAddress2() {
            return address2;
        }

        public void setAddress2(final int address2) {
            this.address2 = address2;
        }

        public int getSize() {
            return size;
        }

        public void setSize(final int size) {
            this.size = size;
        }

        public int getSize2() {
            return size2;
        }

        public void setSize2(final int size2) {
            this.size2 = size2;
        }

        public int getOffset() {
            return offset;
        }

        public void setOffset(final int offset) {
            this.offset = offset;
        }

        public int getAlign() {
            return align;
        }

        public void setAlign(final int align) {
            this.align = align;
        }

        public int getRelocationOffset() {
            return relocationOffset;
        }

        public void setRelocationOffset(final int relocationOffset) {
            this.relocationOffset = relocationOffset;
        }

        public int getNumberOfRelocations() {
            return numberOfRelocations;
        }

        public void setNumberOfRelocations(final int numberOfRelocations) {
            this.numberOfRelocations = numberOfRelocations;
        }

        public int getFlags() {
            return flags;
        }

        public void setFlags(final int flags) {
            this.flags = flags;
        }

        public int getReserved1() {
            return reserved1;
        }

        public void setReserved1(final int reserved1) {
            this.reserved1 = reserved1;
        }

        public int getReserved2() {
            return reserved2;
        }

        public void setReserved2(final int reserved2) {
            this.reserved2 = reserved2;
        }
        
        public int getReserved3() {
            return reserved3;
        }

        public void setReserved3(final int reserved3) {
            this.reserved3 = reserved3;
        }

        public void write(final DataOutput dataOutput) throws IOException {
            Util.writeString(dataOutput, sectionName, 16, '\0');
            Util.writeString(dataOutput, segmentName, 16, '\0');
            dataOutput.writeInt(address);
            if(id == LC_SEGMENT_64) {
                dataOutput.writeInt(address2);
            }
            dataOutput.writeInt(size);
            if(id == LC_SEGMENT_64) {
                dataOutput.writeInt(size2);
            }
            dataOutput.writeInt(offset);
            dataOutput.writeInt(align);
            dataOutput.writeInt(relocationOffset);
            dataOutput.writeInt(numberOfRelocations);
            dataOutput.writeInt(flags);
            dataOutput.writeInt(reserved1);
            dataOutput.writeInt(reserved2);
            if(id == LC_SEGMENT_64) {
                dataOutput.writeInt(reserved3);
            }
        }

        private void readImpl(final DataInput dataInput) throws IOException {
            sectionName = Util.readString(dataInput, 16).trim();
            segmentName = Util.readString(dataInput, 16).trim();
            address = dataInput.readInt();
            if(id == LC_SEGMENT_64) {
                address2 = dataInput.readInt();
            }
            size = dataInput.readInt();
            if(id == LC_SEGMENT_64) {
                size2 = dataInput.readInt();
            }
            offset = dataInput.readInt();
            align = dataInput.readInt();
            relocationOffset = dataInput.readInt();
            numberOfRelocations = dataInput.readInt();
            flags = dataInput.readInt();
            reserved1 = dataInput.readInt();
            reserved2 = dataInput.readInt();
            if(id == LC_SEGMENT_64) {
                reserved3 = dataInput.readInt();
            }
        }

        @Override
        public String toString() {
            String ret = "Section { sectionName: \"" + sectionName + "\""
            + ", segmentName: \"" + segmentName + "\""
            + ", address: 0x" + Util.hex32(address);
            if(id == LC_SEGMENT_64) {
                ret += Util.hex32(address2);
            }
            ret += ", size: 0x" + Util.hex32(size);
            if(id == LC_SEGMENT_64) {
                ret += Util.hex32(size2);
            }
            ret += ", offset: 0x" + Util.hex32(offset)
             + ", align: " + align
             + ", relocationOffset: 0x"
             + Util.hex32(relocationOffset)
             + ", numberOfRelocations: " + numberOfRelocations
             + ", flags: 0x" + Util.hex32(flags)
             + ", reserved1: " + reserved1
             + ", reserved2: " + reserved2;
            if(id == LC_SEGMENT_64) {
                ret += ", reserved3: " + reserved3;
            }
            ret += " }";
            return ret;
        }
    }
}
