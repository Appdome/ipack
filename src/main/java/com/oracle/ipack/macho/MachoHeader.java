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

import com.oracle.ipack.macho.SegmentCommand.Section;
import com.oracle.ipack.util.Util;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.ArrayList;

public final class MachoHeader {
    public static final int CPU_TYPE_ARM64 = 0x0100000C;
    private ArrayList<MachoCommand> commands;

    private int magic;
    private int cpuType;
    private int cpuSubType;
    private int fileType;
    private int flags;
    private int reserved;

    public MachoHeader() {
        commands = new ArrayList<MachoCommand>();
    }

    public MachoCommand findCommand(final int commandId) {
        for (final MachoCommand command: commands) {
            if (command.getId() == commandId) {
                return command;
            }
        }

        return null;
    }

    public SegmentCommand findSegment(final String segmentName) {
        for (final MachoCommand command: commands) {
            if (command.getId() == MachoCommand.LC_SEGMENT || command.getId() == MachoCommand.LC_SEGMENT_64) {
                final SegmentCommand segmentCommand = (SegmentCommand) command;
                if (segmentName.equals(segmentCommand.getSegmentName())) {
                    return segmentCommand;
                }
            }
        }

        return null;
    }
    
    public int getFirstSectionFileOffset()
            throws IOException {
        int lowestOffset = Integer.MAX_VALUE;
        for (final MachoCommand command: commands) {
            if (command.getId() == MachoCommand.LC_SEGMENT || command.getId() == MachoCommand.LC_SEGMENT_64) {
                final SegmentCommand segmentCommand = (SegmentCommand) command;
                final ArrayList<Section> sections = segmentCommand.getSections();
                for (final Section section: sections) {
//                    System.out.println("Segment: " + section.getSegmentName() + " Section: " + section.getSectionName() + " Section size: " + section.getSize() + " Section offset: " + section.getOffset());
                    if (section.getSize() > 0 && section.getOffset() > 0 && section.getOffset() < lowestOffset) {
//                        System.out.println("Updating lowest offset from: " + lowestOffset + " to: " + section.getOffset());
                        lowestOffset = section.getOffset();
                    }
                }
            }
        }
        if (lowestOffset < Integer.MAX_VALUE) {
//            System.out.println("Returning: " + lowestOffset);
            return lowestOffset;
        } else {
//            System.out.println("Returning: 0");
            return 0;
        }
    }

    public void addCommand(final MachoCommand command) {
        commands.add(command);
    }

    public static MachoHeader read(final DataInput dataInput)
            throws IOException {
        final MachoHeader header = new MachoHeader();
        header.readImpl(dataInput);
        return header;
    }

    public int getSize() {
        int size = 7 * 4;
        if(cpuType == CPU_TYPE_ARM64) {
            size += 4;
        }
        for (final MachoCommand command: commands) {
            size += command.getSize();
        }

        return size;
    }

    public int getMagic() {
        return magic;
    }

    public void setMagic(final int magic) {
        this.magic = magic;
    }

    public int getCpuType() {
        return cpuType;
    }

    public void setCpuType(final int cpuType) {
        this.cpuType = cpuType;
    }

    public int getCpuSubType() {
        return cpuSubType;
    }

    public void setCpuSubType(final int cpuSubType) {
        this.cpuSubType = cpuSubType;
    }

    public int getFileType() {
        return fileType;
    }

    public void setFileType(final int fileType) {
        this.fileType = fileType;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(final int flags) {
        this.flags = flags;
    }
    
    public int getReserved() {
        return reserved;
    }

    public void setReserved(final int reserved) {
        this.reserved = reserved;
    }

    public void write(final DataOutput dataOutput) throws IOException {
        dataOutput.writeInt(magic);
        dataOutput.writeInt(cpuType);
        dataOutput.writeInt(cpuSubType);
        dataOutput.writeInt(fileType);
        dataOutput.writeInt(commands.size());
        dataOutput.writeInt(getSizeOfCommands());
        dataOutput.writeInt(flags);
        if(cpuType == CPU_TYPE_ARM64) {
            dataOutput.writeInt(reserved);
        }

        for (final MachoCommand command: commands) {
            command.write(dataOutput);
        }
    }

    private void readImpl(final DataInput dataInput) throws IOException {
        magic = dataInput.readInt();
        cpuType = dataInput.readInt();
        cpuSubType = dataInput.readInt();
        fileType = dataInput.readInt();
        final int numberOfCommands = dataInput.readInt();
        final int sizeOfCommands = dataInput.readInt();
        flags = dataInput.readInt();
        if(cpuType == CPU_TYPE_ARM64) {
            reserved = dataInput.readInt();
        }

        int sizeOfReadCommands = 0;
        commands.clear();
        commands.ensureCapacity(numberOfCommands);
        for (int i = 0; i < numberOfCommands; ++i) {
            final MachoCommand command = MachoCommand.read(dataInput);
            commands.add(command);
            sizeOfReadCommands += command.getSize();
        }

        if (sizeOfCommands != sizeOfReadCommands) {
            throw new IOException("Failed to decode commands");
        }
    }

    private int getSizeOfCommands() {
        int sizeOfCommands = 0;
        for (final MachoCommand command: commands) {
            sizeOfCommands += command.getSize();
        }

        return sizeOfCommands;
    }

    @Override
    public String toString() {
        String ret = "Header { magic: 0x" + Util.hex32(magic)
                + ", cpuType: " + cpuType
                + ", cpuSubType: " + cpuSubType
                + ", fileType: " + fileType
                + ", flags: 0x" + Util.hex32(flags);
        if(cpuType == CPU_TYPE_ARM64) {
            ret += ", reserved: 0x" + Util.hex32(reserved);
        }
        ret += ", commands: " + commands + " }";
        return ret;
    }
}
