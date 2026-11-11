#!/usr/bin/env python3
"""EROFS filesystem extractor - extracts files from EROFS images without root."""

import struct
import os
import sys
import lz4.block

EROFS_SUPER_OFFSET = 1024
EROFS_SUPER_MAGIC = 0xE0F5E1E2

# Inode datalayout
EROFS_INODE_FLAT_PLAIN = 0
EROFS_INODE_COMPRESSED_FULL = 1
EROFS_INODE_FLAT_INLINE = 2
EROFS_INODE_COMPRESSED_COMPACT = 3
EROFS_INODE_CHUNK_BASED = 4

# Inode layout
EROFS_INODE_LAYOUT_COMPACT = 0  # 32 bytes
EROFS_INODE_LAYOUT_EXTENDED = 1  # 64 bytes

# File types
FT_UNKNOWN = 0
FT_REG_FILE = 1
FT_DIR = 2
FT_CHRDEV = 3
FT_BLKDEV = 4
FT_FIFO = 5
FT_SOCK = 6
FT_SYMLINK = 7

# Compression
Z_EROFS_COMPRESSION_LZ4 = 0
Z_EROFS_COMPRESSION_LZMA = 1
Z_EROFS_COMPRESSION_DEFLATE = 2
Z_EROFS_COMPRESSION_ZSTD = 3

Z_EROFS_LCLUSTER_TYPE_PLAIN = 0
Z_EROFS_LCLUSTER_TYPE_HEAD1 = 1
Z_EROFS_LCLUSTER_TYPE_NONHEAD = 2
Z_EROFS_LCLUSTER_TYPE_HEAD2 = 3

Z_EROFS_LI_D0_CBLKCNT = 1 << 11


class ErofsImage:
    def __init__(self, image_path):
        self.f = open(image_path, 'rb')
        self._parse_superblock()
        self._parse_compression_cfgs()

    def _parse_superblock(self):
        self.f.seek(EROFS_SUPER_OFFSET)
        sb = self.f.read(144)
        (self.magic, self.checksum, self.feature_compat, self.blkszbits,
         self.sb_extslots) = struct.unpack_from('<IIIBB', sb, 0)
        if self.magic != EROFS_SUPER_MAGIC:
            raise ValueError(f"Bad magic: {self.magic:#x}")
        self.blksize = 1 << self.blkszbits
        # rb union is at offset 14 (after magic(4)+checksum(4)+feature_compat(4)+blkszbits(1)+sb_extslots(1))
        self.rootnid = struct.unpack_from('<H', sb, 14)[0]
        # inos(8) at offset 16, epoch(8) at 24, fixed_nsec(4) at 32, blocks_lo(4) at 36, meta_blkaddr(4) at 40, xattr_blkaddr(4) at 44
        (self.inos, self.epoch, self.fixed_nsec, self.blocks_lo,
         self.meta_blkaddr, self.xattr_blkaddr) = struct.unpack_from('<QQIIII', sb, 16)
        self.feature_incompat = struct.unpack_from('<I', sb, 64)[0]
        # Check for 48BIT feature
        if self.feature_incompat & 0x80:
            self.rootnid = struct.unpack_from('<Q', sb, 112)[0]
        self.volume_name = sb[48:64].rstrip(b'\x00').decode('utf-8', errors='replace')
        print(f"  EROFS: blksz={self.blksize} rootnid={self.rootnid} meta_blkaddr={self.meta_blkaddr}")
        print(f"  Volume: {self.volume_name} feature_incompat=0x{self.feature_incompat:x}")

    def _parse_compression_cfgs(self):
        self.lz4_max_distance = 65536
        if self.feature_incompat & 0x01:  # LZ4_0PADDING
            pass

    def read_block(self, blkaddr, count=1):
        self.f.seek(blkaddr * self.blksize)
        return self.f.read(self.blksize * count)

    def read_inode(self, nid):
        inode_offset = self.meta_blkaddr * self.blksize + nid * 32
        self.f.seek(inode_offset)
        # First read compact (32 bytes), then decide
        data = self.f.read(64)
        i_format = struct.unpack_from('<H', data, 0)[0]
        version = i_format & 0x01
        datalayout = (i_format >> 1) & 0x07
        if version == EROFS_INODE_LAYOUT_EXTENDED:
            return self._parse_extended_inode(data[:64], i_format, datalayout)
        else:
            return self._parse_compact_inode(data[:32], i_format, datalayout)

    def _parse_compact_inode(self, data, i_format, datalayout):
        (i_xattr_icount, i_mode) = struct.unpack_from('<HH', data, 2)
        i_nb = struct.unpack_from('<H', data, 6)[0]
        i_size = struct.unpack_from('<I', data, 8)[0]
        i_mtime = struct.unpack_from('<I', data, 12)[0]
        i_u = struct.unpack_from('<I', data, 16)[0]
        i_ino = struct.unpack_from('<I', data, 20)[0]
        i_uid = struct.unpack_from('<H', data, 24)[0]
        i_gid = struct.unpack_from('<H', data, 26)[0]
        nlink = 1 if (i_format & (1 << 4)) else i_nb
        return {
            'format': i_format, 'version': 0, 'datalayout': datalayout,
            'mode': i_mode, 'size': i_size, 'nlink': nlink,
            'uid': i_uid, 'gid': i_gid, 'mtime': i_mtime,
            'i_u': i_u, 'xattr_icount': i_xattr_icount,
            'inode_size': 32, 'nid': None,
        }

    def _parse_extended_inode(self, data, i_format, datalayout):
        (i_xattr_icount, i_mode) = struct.unpack_from('<HH', data, 2)
        i_nb = struct.unpack_from('<H', data, 6)[0]
        i_size = struct.unpack_from('<Q', data, 8)[0]
        i_u = struct.unpack_from('<I', data, 16)[0]
        i_ino = struct.unpack_from('<I', data, 20)[0]
        i_uid = struct.unpack_from('<I', data, 24)[0]
        i_gid = struct.unpack_from('<I', data, 28)[0]
        i_mtime = struct.unpack_from('<Q', data, 32)[0]
        i_mtime_nsec = struct.unpack_from('<I', data, 40)[0]
        i_nlink = struct.unpack_from('<I', data, 44)[0]
        return {
            'format': i_format, 'version': 1, 'datalayout': datalayout,
            'mode': i_mode, 'size': i_size, 'nlink': i_nlink,
            'uid': i_uid, 'gid': i_gid, 'mtime': i_mtime,
            'i_u': i_u, 'xattr_icount': i_xattr_icount,
            'inode_size': 64, 'nid': None,
        }

    def get_inode_xattr_size(self, inode):
        icount = inode['xattr_icount']
        if icount == 0:
            return 0
        return 12 + 4 * (icount - 1)

    def read_dir(self, inode):
        """Read directory entries from a directory inode."""
        data = self.read_file_data(inode, inode.get('nid', 0))
        return self._parse_dirents(data)

    def _parse_dirents(self, data):
        """Parse directory entries from raw data."""
        dirents = []
        if len(data) < 12:
            return dirents
        # First dirent
        nid, nameoff, ftype, _ = struct.unpack_from('<QHBB', data, 0)
        # Calculate number of dirents
        # Each dirent is 12 bytes, names follow after all dirents
        # Number of dirents = nameoff_of_first_dirent / 12
        if nameoff == 0:
            return dirents
        num_dirents = nameoff // 12
        for i in range(num_dirents):
            off = i * 12
            if off + 12 > len(data):
                break
            nid, nameoff, ftype, _ = struct.unpack_from('<QHBB', data, off)
            # Get name
            name_start = nameoff
            if i + 1 < num_dirents:
                next_nameoff = struct.unpack_from('<H', data, (i + 1) * 12 + 8)[0]
                name_end = next_nameoff
            else:
                name_end = len(data)
            name = data[name_start:name_end].rstrip(b'\x00').decode('utf-8', errors='replace')
            dirents.append({'nid': nid, 'name': name, 'ftype': ftype})
        return dirents

    def read_file_data(self, inode, nid):
        """Read file data from inode."""
        datalayout = inode['datalayout']
        size = inode['size']
        i_u = inode['i_u']
        xattr_size = self.get_inode_xattr_size(inode)
        inode_size = inode['inode_size']

        if datalayout == EROFS_INODE_FLAT_PLAIN:
            # Uncompressed, data in separate blocks
            startblk = i_u
            nblocks = (size + self.blksize - 1) // self.blksize
            data = b''
            for i in range(nblocks):
                data += self.read_block(startblk + i)
            return data[:size]

        elif datalayout == EROFS_INODE_FLAT_INLINE:
            # Uncompressed with tail-packing inline data
            # inode offset in file = meta_blkaddr * blksize + nid * 32
            inode_offset = self.meta_blkaddr * self.blksize + nid * 32
            data_start = inode_offset + inode_size + xattr_size

            if i_u == 0xFFFFFFFF:
                # All data is inline after inode + xattr
                self.f.seek(data_start)
                data = self.f.read(size)
                return data[:size]

            startblk = i_u
            nblocks = (size + self.blksize - 1) // self.blksize
            data = b''
            if nblocks > 1:
                # Read full blocks except the last
                for i in range(nblocks - 1):
                    data += self.read_block(startblk + i)
                remaining = size - len(data)
                if remaining > 0:
                    # Last part is inline after inode
                    self.f.seek(data_start)
                    data += self.f.read(remaining)
            else:
                # All data is inline after inode + xattr
                self.f.seek(data_start)
                data = self.f.read(size)
            return data[:size]

        elif datalayout == EROFS_INODE_CHUNK_BASED:
            # Chunk-based file
            chunk_format = i_u & 0xFFFF
            chunk_blkbits = chunk_format & 0x1F
            has_indexes = (chunk_format & 0x20) != 0
            chunksize = self.blksize << chunk_blkbits
            nchunks = (size + chunksize - 1) // chunksize

            if has_indexes:
                # Read chunk indexes (8 bytes each)
                inode_offset = self.meta_blkaddr * self.blksize + nid * 32
                idx_offset = inode_offset + inode_size + xattr_size
                self.f.seek(idx_offset)
                idx_data = self.f.read(8 * nchunks)
                data = b''
                for i in range(nchunks):
                    startblk_hi, device_id, startblk_lo = struct.unpack_from('<HHI', idx_data, i * 8)
                    startblk = startblk_lo | (startblk_hi << 32)
                    read_size = min(chunksize, size - len(data))
                    if startblk == 0xFFFFFFFF or (startblk_hi == 0xFFFF and startblk_lo == 0xFFFF):
                        # Hole
                        data += b'\x00' * read_size
                    else:
                        self.f.seek(startblk * self.blksize)
                        data += self.f.read(read_size)
                return data[:size]
            else:
                # 4-byte block array
                inode_offset = self.meta_blkaddr * self.blksize + nid * 32
                idx_offset = inode_offset + inode_size + xattr_size
                self.f.seek(idx_offset)
                idx_data = self.f.read(4 * nchunks)
                data = b''
                for i in range(nchunks):
                    startblk = struct.unpack_from('<I', idx_data, i * 4)[0]
                    read_size = min(chunksize, size - len(data))
                    if startblk == 0xFFFFFFFF:
                        data += b'\x00' * read_size
                    else:
                        self.f.seek(startblk * self.blksize)
                        data += self.f.read(read_size)
                return data[:size]

        elif datalayout in (EROFS_INODE_COMPRESSED_FULL, EROFS_INODE_COMPRESSED_COMPACT):
            return self._read_compressed_data(inode, nid)

        return b''

    def _read_compressed_data(self, inode, nid):
        """Read compressed file data."""
        size = inode['size']
        i_u = inode['i_u']
        inode_size = inode['inode_size']
        xattr_size = self.get_inode_xattr_size(inode)
        datalayout = inode['datalayout']

        # Read the map header (8 bytes) after inode + xattr
        inode_offset = self.meta_blkaddr * self.blksize + nid * 32
        map_header_offset = inode_offset + inode_size + xattr_size

        self.f.seek(map_header_offset)
        mh_data = self.f.read(8)
        h_fragmentoff, h_advise = struct.unpack_from('<IH', mh_data, 0)
        h_algorithmtype = mh_data[6]
        h_clusterbits = mh_data[7]

        alg_type = h_algorithmtype & 0x0F
        cluster_bits = h_clusterbits & 0x0F
        lcluster_size = self.blksize << cluster_bits

        total_clusters = (size + lcluster_size - 1) // lcluster_size

        # Read lcluster indexes
        if datalayout == EROFS_INODE_COMPRESSED_COMPACT:
            # Compact: indexes start right after map header
            idx_start = map_header_offset + 8
            idx_size = 4  # compact uses 4-byte indexes
        else:
            # Full: indexes start after map header + 8
            idx_start = map_header_offset + 8 + 8
            idx_size = 8  # full uses 8-byte indexes

        # For compact mode with COMPACTED_2B
        if h_advise & 0x0001:  # COMPACTED_2B
            idx_size = 4 + 2 + 4  # actually variable...

        # Simplified: read 8-byte lcluster indexes
        self.f.seek(idx_start)
        idx_data = self.f.read(8 * total_clusters)

        data = b''
        for i in range(total_clusters):
            if i * 8 + 8 > len(idx_data):
                break
            di_advise, di_clusterofs = struct.unpack_from('<HH', idx_data, i * 8)
            lcluster_type = di_advise & 0x03
            remaining = size - len(data)
            read_size = min(lcluster_size, remaining)

            if lcluster_type == Z_EROFS_LCLUSTER_TYPE_PLAIN:
                # Uncompressed
                blkaddr = struct.unpack_from('<I', idx_data, i * 8 + 4)[0]
                if blkaddr == 0xFFFFFFFF:
                    data += b'\x00' * read_size
                else:
                    self.f.seek(blkaddr * self.blksize)
                    data += self.f.read(read_size)
            elif lcluster_type in (Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_HEAD2):
                # Head of compressed cluster
                blkaddr = struct.unpack_from('<I', idx_data, i * 8 + 4)[0]
                if blkaddr == 0xFFFFFFFF:
                    data += b'\x00' * read_size
                    continue
                # Read compressed data - we need to figure out how many blocks
                # For now, try reading and decompressing
                # The compressed size is determined by the next HEAD or end
                compressed_blocks = 1
                # Look ahead for next HEAD
                for j in range(i + 1, total_clusters):
                    if j * 8 + 8 > len(idx_data):
                        break
                    next_advise = struct.unpack_from('<H', idx_data, j * 8)[0]
                    next_type = next_advise & 0x03
                    if next_type in (Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_HEAD2):
                        # Found next head, count blocks in between
                        if next_type == Z_EROFS_LCLUSTER_TYPE_NONHEAD:
                            # Check if D0_CBLKCNT
                            if next_advise & Z_EROFS_LI_D0_CBLKCNT:
                                delta0 = struct.unpack_from('<H', idx_data, j * 8 + 4)[0]
                                compressed_blocks = delta0
                        break
                    elif next_type == Z_EROFS_LCLUSTER_TYPE_NONHEAD:
                        if next_advise & Z_EROFS_LI_D0_CBLKCNT:
                            delta0 = struct.unpack_from('<H', idx_data, j * 8 + 4)[0]
                            compressed_blocks = delta0
                            break

                # Read compressed data
                self.f.seek(blkaddr * self.blksize)
                compressed_data = self.f.read(self.blksize * compressed_blocks)

                # Decompress with LZ4
                try:
                    if alg_type == Z_EROFS_COMPRESSION_LZ4:
                        decompressed = lz4.block.decompress(
                            compressed_data, uncompressed_size=lcluster_size
                        )
                        data += decompressed[:read_size]
                    else:
                        print(f"    Warning: unsupported compression alg {alg_type}")
                        data += b'\x00' * read_size
                except Exception as e:
                    print(f"    Warning: decompress failed at cluster {i}: {e}")
                    data += b'\x00' * read_size
            elif lcluster_type == Z_EROFS_LCLUSTER_TYPE_NONHEAD:
                # Part of previous compressed cluster, skip
                pass

        return data[:size]

    def extract(self, out_dir, nid=None, path="/"):
        """Extract all files starting from the given nid."""
        if nid is None:
            nid = self.rootnid
        inode = self.read_inode(nid)
        inode['nid'] = nid
        mode = inode['mode']
        is_dir = (mode & 0xF000) == 0x4000
        is_symlink = (mode & 0xF000) == 0xA000
        is_reg = (mode & 0xF000) == 0x8000

        if is_dir:
            # Create directory
            out_path = os.path.join(out_dir, path.lstrip('/'))
            os.makedirs(out_path, exist_ok=True)
            # Read directory entries
            dirents = self.read_dir(inode)
            for de in dirents:
                if de['name'] in ('.', '..'):
                    continue
                child_path = path.rstrip('/') + '/' + de['name']
                self.extract(out_dir, de['nid'], child_path)
        elif is_symlink:
            # Read symlink target
            target = self.read_file_data(inode, nid).decode('utf-8', errors='replace')
            out_path = os.path.join(out_dir, path.lstrip('/'))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            try:
                os.symlink(target, out_path)
            except:
                pass
        elif is_reg:
            # Regular file
            out_path = os.path.join(out_dir, path.lstrip('/'))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            data = self.read_file_data(inode, nid)
            with open(out_path, 'wb') as f:
                f.write(data)
        else:
            # Other file types (device, fifo, socket) - skip
            pass

    def close(self):
        self.f.close()


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <image.img> <output_dir>")
        sys.exit(1)
    img_path = sys.argv[1]
    out_dir = sys.argv[2]
    print(f"Extracting {img_path} -> {out_dir}")
    img = ErofsImage(img_path)
    os.makedirs(out_dir, exist_ok=True)
    img.extract(out_dir)
    img.close()
    print(f"Done: {img_path} -> {out_dir}")


if __name__ == '__main__':
    main()
