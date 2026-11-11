#!/usr/bin/env python3
"""Batch extract all db files from EROFS image using dump.erofs for extent info."""

import subprocess, re, os, lz4.block, sqlite3, struct

IMG = 'odm_a.img'
OUT_DIR = '/tmp/erofs_db'

# All regular db files (nid, relative_path)
DB_FILES = [
    (407, 'port_select.db'),
    (23168, 'mt6993/ParameterDB.db'),
    (23186, 'mt6993/sw_top_control_data.db'),
    (23191, 'mt6993/top_control_data.db'),
    (37110, 'mt6993/ISP_info.db'),
    (937195, 'mt6993/ISP_info.db'),  # tuning_DB_aov version
    (459, 'mt6993/ParameterDB_ae.db'),
    (477, 'mt6993/ParameterDB_af.db'),
    (13568, 'mt6993/ParameterDB_awb.db'),
    (497, 'mt6993/ParameterDB_awbsync.db'),
    (13648, 'mt6993/ParameterDB_feature.db'),
    (13663, 'mt6993/ParameterDB_flash.db'),
    (13674, 'mt6993/ParameterDB_flashcali.db'),
    (13686, 'mt6993/ParameterDB_flicker.db'),
    (23211, 'mt6993/ParameterDB_pd.db'),
    (23223, 'mt6993/ParameterDB_pipeline.db'),
    (36864, 'mt6993/ParameterDB_tone.db'),
]

def get_extents(img, nid):
    """Use dump.erofs to get extent info for a file."""
    result = subprocess.run(
        ['dump.erofs', f'--nid={nid}', '-e', img],
        capture_output=True, text=True
    )
    # Check file type
    if 'symlink' in result.stdout:
        return None, 'symlink'
    if 'directory' in result.stdout:
        return None, 'directory'
    
    # Parse file size
    size_match = re.search(r'Size:\s+(\d+)', result.stdout)
    file_size = int(size_match.group(1)) if size_match else 0
    
    # Parse extents
    extents = []
    for line in result.stdout.split('\n'):
        m = re.match(r'\s*(\d+):\s+(\d+)\.\.\s*(\d+)\s+\|\s+(\d+)\s*:\s+(\d+)\.\.\s*(\d+)\s+\|\s+(\d+)', line)
        if m:
            extents.append({
                'idx': int(m.group(1)),
                'logical_start': int(m.group(2)),
                'logical_end': int(m.group(3)),
                'logical_len': int(m.group(4)),
                'physical_start': int(m.group(5)),
                'physical_end': int(m.group(6)),
                'physical_len': int(m.group(7)),
            })
    return extents, file_size

def extract_file(img, nid, out_path):
    """Extract a file from EROFS image."""
    extents, file_size = get_extents(img, nid)
    
    if extents is None:
        print(f"  Skip (type={file_size})")
        return False
    
    if not extents:
        print(f"  No extents found")
        return False
    
    result = bytearray(file_size)
    
    with open(img, 'rb') as f:
        for ext in extents:
            pblk_start = ext['physical_start']
            pblk_end = ext['physical_end']
            logical_start = ext['logical_start']
            logical_end = ext['logical_end']
            target_len = ext['logical_len']
            
            # Read exactly physical_len bytes of compressed data
            f.seek(pblk_start)
            compressed = f.read(ext['physical_len'])
            
            # Try decompressing with different uncompressed sizes
            decomp = None
            # Build a comprehensive list of sizes to try
            sizes = sorted(set([
                target_len,
                target_len + 4096,
                target_len + 8192,
                target_len + 16384,
                32768, 49152, 65536, 98304, 131072, 196608, 262144,
                524288, 1048576
            ]))
            for usize in sizes:
                try:
                    decomp = lz4.block.decompress(compressed, uncompressed_size=usize)
                    break
                except:
                    continue
            
            if decomp is None:
                # Try finding the compressed stream start by scanning for first nonzero byte
                for scan_start in range(0, min(len(compressed), 4096)):
                    if compressed[scan_start] == 0:
                        continue
                    for usize in sizes:
                        try:
                            decomp = lz4.block.decompress(compressed[scan_start:], uncompressed_size=usize)
                            break
                        except:
                            continue
                    if decomp is not None:
                        break
            
            if decomp is not None:
                # If decompressed data is larger than target_len,
                # it may contain clusterofs padding at the beginning
                if len(decomp) > target_len:
                    # Find the actual data start by looking for the offset
                    # where the remaining data matches target_len
                    offset_in_decomp = len(decomp) - target_len
                    if offset_in_decomp > 0 and offset_in_decomp < 8192:
                        decomp = decomp[offset_in_decomp:]
                copy_len = min(len(decomp), logical_end - logical_start)
                result[logical_start:logical_start + copy_len] = decomp[:copy_len]
            else:
                print(f"  Extent {ext['idx']}: FAILED to decompress (physical {pblk_start}..{pblk_end})")
                return False
    
    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(result)
    print(f"  Extracted {len(result)} bytes")
    return True

def analyze_db(db_path):
    """Analyze a SQLite database file."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute('PRAGMA integrity_check')
        integrity = cur.fetchone()[0]
        
        cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = cur.fetchall()
        
        info = {'integrity': integrity, 'tables': [], 'path': db_path}
        for tname, tsql in tables:
            cur.execute(f'SELECT count(*) FROM "{tname}"')
            count = cur.fetchone()[0]
            cur.execute(f'PRAGMA table_info("{tname}")')
            cols = [(c[1], c[2]) for c in cur.fetchall()]
            cur.execute(f'SELECT * FROM "{tname}" LIMIT 5')
            sample = []
            for r in cur.fetchall():
                row = []
                for v in r:
                    if isinstance(v, (bytes, bytearray)):
                        row.append(f'<BLOB {len(v)} bytes>')
                    elif isinstance(v, str) and len(v) > 100:
                        row.append(v[:100] + '...')
                    else:
                        row.append(v)
                sample.append(row)
            
            # Get unique values for small tables
            unique_values = {}
            if count <= 1000:
                for col_name, col_type in cols:
                    try:
                        cur.execute(f'SELECT DISTINCT "{col_name}" FROM "{tname}"')
                        vals = [r[0] for r in cur.fetchall()]
                        if len(vals) <= 50:
                            unique_values[col_name] = sorted(vals) if all(isinstance(v, (int, float)) for v in vals if v is not None) else vals
                    except:
                        pass
            
            info['tables'].append({
                'name': tname,
                'sql': tsql,
                'count': count,
                'columns': cols,
                'sample': sample,
                'unique_values': unique_values,
            })
        conn.close()
        return info
    except Exception as e:
        return {'error': str(e), 'path': db_path}

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    
    extracted = {}
    
    for nid, name in DB_FILES:
        out_path = os.path.join(OUT_DIR, name.replace('/', '_'))
        print(f"Extracting {name} (nid={nid})...")
        if extract_file(IMG, nid, out_path):
            extracted[out_path] = name
    
    # Analyze all extracted db files
    print("\n" + "="*80)
    print("ANALYSIS RESULTS")
    print("="*80)
    for db_path, db_name in sorted(extracted.items()):
        print(f"\n--- {db_name} ---")
        info = analyze_db(db_path)
        if 'error' in info:
            print(f"  ERROR: {info['error']}")
        else:
            print(f"  Integrity: {info['integrity']}")
            for t in info['tables']:
                print(f"  Table: {t['name']} ({t['count']} rows)")
                print(f"    Columns: {t['columns']}")
                if t['unique_values']:
                    for col, vals in t['unique_values'].items():
                        print(f"    {col} unique values: {vals}")
                for s in t['sample']:
                    print(f"    Sample: {s}")

if __name__ == '__main__':
    main()
