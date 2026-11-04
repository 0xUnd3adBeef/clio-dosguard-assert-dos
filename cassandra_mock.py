#!/usr/bin/env python3
"""
Minimal AI Generated Cassandra CQL native-protocol v4 mock for reproducing a vuln on Clio without spinning up a whole infra.

Returns just enough to get past Clio's backend init so the HTTP server starts.

Protocol: https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec
"""
import socket, struct, threading, uuid as _uuid

OP_OPTIONS   = 0x05
OP_SUPPORTED = 0x06
OP_STARTUP   = 0x01
OP_READY     = 0x02
OP_QUERY     = 0x07
OP_RESULT    = 0x08
OP_PREPARE   = 0x09
OP_EXECUTE   = 0x0A
OP_REGISTER  = 0x0B
OP_BATCH     = 0x0D

def fr(stream, opcode, body=b''):
    return struct.pack('>BBHBI', 0x84, 0x00, stream, opcode, len(body)) + body

def s(t):                      # [string]
    b = t.encode(); return struct.pack('>H', len(b)) + b

def cell(b):                   # row cell bytes
    if b is None: return struct.pack('>i', -1)
    return struct.pack('>i', len(b)) + b

def set_text(*elems):          # set<text> wire encoding
    out = struct.pack('>i', len(elems))
    for e in elems:
        b = e.encode(); out += struct.pack('>i', len(b)) + b
    return out

T_TEXT   = 0x000A
T_UUID   = 0x000C
T_INET   = 0x0010
T_SET    = 0x0022

# ---- responses ---------------------------------------------------------------

def mk_supported(stream):
    body  = struct.pack('>H', 2)
    body += s('CQL_VERSION') + struct.pack('>H', 1) + s('3.0.0')
    body += s('COMPRESSION') + struct.pack('>H', 0)
    return fr(stream, OP_SUPPORTED, body)

def mk_void(stream):
    return fr(stream, OP_RESULT, struct.pack('>I', 1))

_prep_n = 0
def mk_prepared(stream, query=''):
    global _prep_n; _prep_n += 1
    qid  = struct.pack('>H', _prep_n)
    body = struct.pack('>I', 4)                     # kind=PREPARED
    body += struct.pack('>H', len(qid)) + qid       # query_id

    # Choose param types based on the query.
    # ClusterCommunicationService::doWrite calls writeNodeMessage which executes:
    #   UPDATE clio.nodes_chat SET message = ? WHERE node_id = ?
    # bind order: (Text p0, UUID p1)
    # Declaring the wrong type causes cass_statement_bind_* to return
    # CASS_ERROR_LIB_INVALID_VALUE_TYPE, which bindAt() re-throws as logic_error.
    qu = query.upper()
    if 'NODES_CHAT' in qu and 'UPDATE' in qu:
        param_types = [T_TEXT, T_UUID]   # message TEXT, node_id UUID
    else:
        param_types = [T_TEXT] * 50      # 50 TEXT slots covers all other queries

    N = len(param_types)
    # param_metadata: GLOBAL_TABLES_SPEC so we only emit keyspace+table once
    body += struct.pack('>III', 0x0001, N, 0)       # flags=GLOBAL_TABLES_SPEC, count=N, pk_count=0
    body += s('clio') + s('mock')                   # global keyspace + table
    for i, t in enumerate(param_types):
        body += s(f'p{i}') + struct.pack('>H', t)

    # result_metadata: no columns, no special flags
    # (NO_METADATA here causes "Expected metadata" error in EXECUTE responses)
    body += struct.pack('>II', 0, 0)                # flags=0, count=0

    return fr(stream, OP_RESULT, body)

def mk_rows_empty(stream):
    # ROWS kind=2, flags=0 (NOT NO_METADATA -- that caused the driver error),
    # columns_count=0, rows_count=0
    body  = struct.pack('>I', 2)    # kind=ROWS
    body += struct.pack('>II', 0, 0)  # flags=0, columns_count=0
    body += struct.pack('>I', 0)      # rows_count=0
    return fr(stream, OP_RESULT, body)

def mk_system_local(stream):
    COLS = [
        ('key',                     T_TEXT, None),
        ('cluster_name',            T_TEXT, None),
        ('data_center',             T_TEXT, None),
        ('rack',                    T_TEXT, None),
        ('partitioner',             T_TEXT, None),
        ('tokens',                  T_SET,  T_TEXT),
        ('release_version',         T_TEXT, None),
        ('host_id',                 T_UUID, None),
        ('rpc_address',             T_INET, None),
        ('native_protocol_version', T_TEXT, None),
        ('bootstrapped',            T_TEXT, None),
        ('broadcast_address',       T_INET, None),
    ]
    body  = struct.pack('>I', 2)                         # kind=ROWS
    body += struct.pack('>II', 0x0001, len(COLS))        # flags=GLOBAL_TABLES_SPEC, count
    body += s('system') + s('local')
    for col, typ, sub in COLS:
        body += s(col) + struct.pack('>H', typ)
        if typ == T_SET: body += struct.pack('>H', sub)
    body += struct.pack('>I', 1)                         # 1 row
    body += cell(b'local')
    body += cell(b'Test Cluster')
    body += cell(b'datacenter1')
    body += cell(b'rack1')
    body += cell(b'org.apache.cassandra.dht.Murmur3Partitioner')
    body += cell(set_text('-9223372036854775808', '0', '9223372036854775807'))
    body += cell(b'3.11.15')
    body += cell(_uuid.UUID('12345678-1234-5678-1234-567812345678').bytes)
    body += cell(b'\x7f\x00\x00\x01')
    body += cell(b'4')
    body += cell(b'COMPLETED')
    body += cell(b'\x7f\x00\x00\x01')
    return fr(stream, OP_RESULT, body)

def mk_system_peers(stream):
    body  = struct.pack('>I', 2)
    body += struct.pack('>II', 0x0001, 1)               # GLOBAL_TABLES_SPEC, 1 col
    body += s('system') + s('peers')
    body += s('peer') + struct.pack('>H', T_INET)
    body += struct.pack('>I', 0)                        # 0 rows
    return fr(stream, OP_RESULT, body)

# ---- client handler ----------------------------------------------------------

def handle(conn, addr):
    tag = f"{addr[0]}:{addr[1]}"
    print(f"[+] {tag}", flush=True)
    buf = b''
    try:
        while True:
            chunk = conn.recv(8192)
            if not chunk: break
            buf += chunk
            while len(buf) >= 9:
                ver, flags, stream, op, length = struct.unpack_from('>BBHBI', buf)
                if len(buf) < 9 + length: break
                body, buf = buf[9:9+length], buf[9+length:]

                if op == OP_OPTIONS:
                    conn.sendall(mk_supported(stream))
                elif op in (OP_STARTUP, OP_REGISTER):
                    conn.sendall(fr(stream, OP_READY))
                elif op == OP_QUERY:
                    qlen = struct.unpack_from('>I', body)[0]
                    q = body[4:4+qlen].decode('utf-8', errors='replace').strip()
                    print(f"  Q: {q[:100]}", flush=True)
                    qu = q.upper()
                    if 'SYSTEM.LOCAL' in qu:
                        conn.sendall(mk_system_local(stream))
                    elif 'SYSTEM.PEERS' in qu:
                        conn.sendall(mk_system_peers(stream))
                    else:
                        # Return empty ROWS for everything (SELECT and DML alike).
                        # VOID responses cause cass_future_get_result to return NULL,
                        # which makes ManagedObject throw std::runtime_error.
                        conn.sendall(mk_rows_empty(stream))
                elif op == OP_PREPARE:
                    qlen = struct.unpack_from('>I', body)[0]
                    q = body[4:4+qlen].decode('utf-8', errors='replace').strip()
                    print(f"  P{_prep_n+1}: {q[:80]}", flush=True)
                    conn.sendall(mk_prepared(stream, q))
                elif op in (OP_EXECUTE, OP_BATCH):
                    conn.sendall(mk_rows_empty(stream))
                else:
                    conn.sendall(mk_void(stream))
    except Exception as e:
        print(f"  err: {e}", flush=True)
    finally:
        conn.close()
        print(f"[-] {tag}", flush=True)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 9042))
srv.listen(32)
print('[*] CQL mock on 127.0.0.1:9042', flush=True)
while True:
    c, a = srv.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()
