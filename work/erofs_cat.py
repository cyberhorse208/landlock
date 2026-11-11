#!/usr/bin/env python3
"""Extract a single file from EROFS image by nid, with correct compact index parsing and pblk calculation."""

import struct, lz4.block, sys, os

EROFS_SUPER_OFFSET = 1024

Z_EROFS_LCLUSTER_TYPE_PLAIN = 0
Z_EROFS_LCLUSTER_TYPE_HEAD1 = 1
Z_EROFS_LCLUSTER_TYPE_NONHEAD = 2
Z_EROFS_LCLUSTER_TYPE_HEAD2 = 3

Z_EROFS_ADVISE_COMPACTED_2B = 0x0001
Z_EROFS_ADVISE_BIG_PCLUSTER_1 = 0x0002
Z_EROFS_LI_D0_CBLKCNT = 1 << 11


def ilog2(n):
    if n <= 0:
        return 0
    r = 0
    while n > 1:
        n >>= 1
        r += 1
    return r


def round_up(n, align):
    return (n + align - 1) // align * align


def round_down(n, align):
    return n // align * align


def decode_compactedbits(lobits, data, bit_pos):
    """Decode compacted bits at bit_pos in data. Returns (lo, type)."""
    byte_pos = bit_pos // 8
    if byte_pos + 4 > len(data):
        return 0, 0
    v = struct.unpack_from('<I', data, byte_pos)[0] >> (bit_pos & 7)
    lo = v & ((1 << lobits) - 1)
    type_ = (v >> lobits) & 3
    return lo, type_


def extract_erofs_file(img_path, nid, verbose=False):
    f = open(img_path, 'rb')
    f.seek(EROFS_SUPER_OFFSET)
    sb = f.read(144)
    blkszbits = sb[12]
    blksize = 1 << blkszbits
    meta_blkaddr = struct.unpack_from('<I', sb, 40)[0]

    # Read inode
    inode_offset = meta_blkaddr * blksize + nid * 32
    f.seek(inode_offset)
    data = f.read(64)
    i_format = struct.unpack_from('<H', data, 0)[0]
    i_xattr_icount = struct.unpack_from('<H', data, 2)[0]
    i_mode = struct.unpack_from('<H', data, 4)[0]
    i_size = struct.unpack_from('<I', data, 8)[0]
    i_u = struct.unpack_from('<I', data, 16)[0]
    version = i_format & 1
    datalayout = (i_format >> 1) & 7
    inode_size = 64 if version == 1 else 32

    xattr_size = 12 + 4 * (i_xattr_icount - 1) if i_xattr_icount > 0 else 0

    if verbose:
        print(f"nid={nid}, i_size={i_size}, datalayout={datalayout}, version={version}")
        print(f"inode_offset={inode_offset}, inode_size={inode_size}, xattr_size={xattr_size}")

    # Handle different datalayouts
    if datalayout == 0:  # FLAT_PLAIN
        startblk = i_u
        nblocks = (i_size + blksize - 1) // blksize
        result = b''
        for i in range(nblocks):
            f.seek((startblk + i) * blksize)
            result += f.read(blksize)
        f.close()
        return result[:i_size]

    if datalayout == 2:  # FLAT_INLINE
        if i_u == 0xFFFFFFFF:
            f.seek(inode_offset + inode_size + xattr_size)
            result = f.read(i_size)
            f.close()
            return result[:i_size]
        startblk = i_u
        nblocks = (i_size + blksize - 1) // blksize
        result = b''
        if nblocks > 1:
            for i in range(nblocks - 1):
                f.seek((startblk + i) * blksize)
                result += f.read(blksize)
            remaining = i_size - len(result)
            f.seek(inode_offset + inode_size + xattr_size)
            result += f.read(remaining)
        else:
            f.seek(inode_offset + inode_size + xattr_size)
            result = f.read(i_size)
        f.close()
        return result[:i_size]

    if datalayout != 3:  # Only handle COMPRESSED_COMPACT
        f.close()
        return None

    # COMPRESSED_COMPACT
    iloc = inode_offset
    ebase_abs = 8 + round_up(iloc + inode_size + xattr_size, 8)

    # Read map header
    map_header_offset = iloc + inode_size + xattr_size
    f.seek(map_header_offset)
    mh = f.read(8)
    h_advise = struct.unpack_from('<H', mh, 4)[0]
    h_algorithmtype = mh[6]
    h_clusterbits = mh[7]

    alg_type = h_algorithmtype & 0x0F
    lclusterbits = blkszbits + (h_clusterbits & 0x0F)
    lcluster_size = 1 << lclusterbits
    totalidx = (i_size + lcluster_size - 1) // lcluster_size

    if verbose:
        print(f"ebase_abs={ebase_abs}, h_advise=0x{h_advise:04x}, lclusterbits={lclusterbits}")
        print(f"lcluster_size={lcluster_size}, totalidx={totalidx}")
        print(f"alg_type={alg_type}, h_clusterbits={h_clusterbits}")

    # Compact index parameters
    compacted_4b_initial = ((32 - ebase_abs % 32) // 4) & 7
    compacted_2b = 0
    if (h_advise & Z_EROFS_ADVISE_COMPACTED_2B) and compacted_4b_initial < totalidx:
        compacted_2b = (totalidx - compacted_4b_initial) // 16 * 16

    big_pcluster = bool(h_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1)

    if verbose:
        print(f"compacted_4b_initial={compacted_4b_initial}, compacted_2b={compacted_2b}, big_pcluster={big_pcluster}")

    # Calculate total index bytes
    remaining_count = max(0, totalidx - compacted_4b_initial - compacted_2b)
    total_idx_bytes = compacted_4b_initial * 4 + compacted_2b * 2 + remaining_count * 4

    # Read index data
    idx_start = ebase_abs
    f.seek(idx_start)
    idx_raw = f.read(total_idx_bytes + 32)

    # Decode all lcluster indexes
    clusters = []
    for lcn in range(totalidx):
        pos = ebase_abs
        amortizedshift = 2  # 4 bytes

        lcn_rel = lcn
        if lcn >= compacted_4b_initial:
            pos += compacted_4b_initial * 4
            lcn_rel = lcn - compacted_4b_initial
            if lcn_rel < compacted_2b:
                amortizedshift = 1  # 2 bytes
            else:
                pos += compacted_2b * 2
                lcn_rel -= compacted_2b

        pos += lcn_rel * (1 << amortizedshift)

        # vcnt and encodebits
        if (1 << amortizedshift) == 4 and lclusterbits <= 14:
            vcnt = 2
        elif (1 << amortizedshift) == 2 and lclusterbits <= 12:
            vcnt = 16
        else:
            clusters.append({'type': -1, 'lo': 0, 'lcn': lcn})
            continue

        lobits = max(lclusterbits, ilog2(Z_EROFS_LI_D0_CBLKCNT) + 1)
        encodebits = (((vcnt << amortizedshift) - 4) * 8) >> ilog2(vcnt)

        # Pack info
        pack_size = vcnt << amortizedshift
        pack_start_abs = round_down(pos, pack_size)
        pack_start_in_raw = pack_start_abs - idx_start

        # Index within pack
        bytes_in_pack = pos - pack_start_abs
        i_in_pack = bytes_in_pack >> amortizedshift

        # Bit position within idx_raw
        bit_pos_in_raw = (pack_start_in_raw * 8) + (encodebits * i_in_pack)

        lo, type_ = decode_compactedbits(lobits, idx_raw, bit_pos_in_raw)

        cluster_info = {'type': type_, 'lo': lo, 'lcn': lcn}

        if type_ == Z_EROFS_LCLUSTER_TYPE_NONHEAD:
            if lo & Z_EROFS_LI_D0_CBLKCNT:
                cluster_info['compressedblks'] = lo & ~Z_EROFS_LI_D0_CBLKCNT
                cluster_info['delta0'] = 1
            else:
                cluster_info['delta0'] = lo
        elif type_ in (Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_HEAD2):
            cluster_info['clusterofs'] = lo
            cluster_info['delta0'] = 0

            # Calculate pblk by walking backwards in the pack
            nblk = 0 if big_pcluster else 1
            i = i_in_pack
            while i > 0:
                i -= 1
                lo2, type2 = decode_compactedbits(lobits, idx_raw, (pack_start_in_raw * 8) + (encodebits * i))
                if type2 == Z_EROFS_LCLUSTER_TYPE_NONHEAD:
                    if big_pcluster:
                        if lo2 & Z_EROFS_LI_D0_CBLKCNT:
                            i -= 1
                            nblk += lo2 & ~Z_EROFS_LI_D0_CBLKCNT
                            continue
                        if lo2 <= 1:
                            break
                        i -= lo2 - 2
                        continue
                    else:
                        i -= lo2
                if i >= 0:
                    nblk += 1

            # Read 4-byte base value from end of pack
            base_offset = pack_start_in_raw + pack_size - 4
            if base_offset + 4 <= len(idx_raw):
                base_value = struct.unpack_from('<I', idx_raw, base_offset)[0]
                cluster_info['pblk'] = base_value + nblk
                cluster_info['nblk'] = nblk
            else:
                cluster_info['pblk'] = 0xFFFFFFFF
                cluster_info['nblk'] = nblk

        clusters.append(cluster_info)

        if verbose:
            print(f"  lcn={lcn}: type={type_}, lo={lo}", end="")
            if 'clusterofs' in cluster_info:
                print(f", clusterofs={cluster_info['clusterofs']}, pblk={cluster_info['pblk']}, nblk={cluster_info['nblk']}")
            elif 'delta0' in cluster_info:
                extra = f", compressedblks={cluster_info['compressedblks']}" if 'compressedblks' in cluster_info else ""
                print(f", delta0={cluster_info['delta0']}{extra}")
            else:
                print()

    # Decompress: find HEAD clusters and their extents
    result = bytearray(i_size)
    i = 0
    while i < totalidx:
        c = clusters[i]
        if c['type'] in (Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_HEAD2):
            pblk = c.get('pblk', 0xFFFFFFFF)
            clusterofs = c.get('clusterofs', 0)

            # Count how many logical clusters this HEAD covers
            extent_len = 1
            j = i + 1
            while j < totalidx:
                nc = clusters[j]
                if nc['type'] == Z_EROFS_LCLUSTER_TYPE_NONHEAD:
                    extent_len += 1
                    j += 1
                else:
                    break

            # Decompressed size for this extent
            decomp_size = extent_len * lcluster_size

            if pblk == 0xFFFFFFFF:
                if verbose:
                    print(f"  HEAD lcn={i}: pblk=INVALID, filling zeros")
                i = j
                continue

            compressedblks = c.get('compressedblks', 1)
            f.seek(pblk * blksize)
            compressed = f.read(blksize * compressedblks)

            decompressed = None
            # Try the expected size first, then fallbacks
            for usize in [decomp_size, decomp_size + lcluster_size, 32768, 40960, 49152, 65536]:
                try:
                    decompressed = lz4.block.decompress(compressed, uncompressed_size=usize)
                    break
                except:
                    continue

            if decompressed is not None:
                # Place data at the correct offset: (lcn * lcluster_size) + clusterofs
                offset = i * lcluster_size + clusterofs
                copy_size = min(len(decompressed), i_size - offset)
                if copy_size > 0:
                    result[offset:offset + copy_size] = decompressed[:copy_size]
                if verbose:
                    print(f"  HEAD lcn={i}: pblk={pblk}, clusterofs={clusterofs}, offset={offset}, extent_len={extent_len}, decomp_size={decomp_size}, got={len(decompressed)}")
            else:
                if verbose:
                    print(f"  HEAD lcn={i}: pblk={pblk}, decompress FAILED")

            i = j
        else:
            i += 1

    f.close()
    return bytes(result)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <image.img> <nid> [output_file] [-v]")
        sys.exit(1)
    img_path = sys.argv[1]
    nid = int(sys.argv[2])
    out_file = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != '-v' else None
    verbose = '-v' in sys.argv

    data = extract_erofs_file(img_path, nid, verbose)
    if data is None:
        print("Failed to extract or unsupported datalayout", file=sys.stderr)
        sys.exit(1)

    if out_file:
        with open(out_file, 'wb') as f:
            f.write(data)
        print(f"Extracted {len(data)} bytes to {out_file}")
    else:
        sys.stdout.buffer.write(data)


if __name__ == '__main__':
    main()
