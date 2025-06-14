import os
import struct
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_zip_file_list(zip_url, headers=None):
    session = requests.Session()
    headers = headers or {}

    # HEAD request to get file size
    head = session.head(zip_url, allow_redirects=True, headers=headers)
    if head.status_code != 200:
        return {"error": f"Failed to access ZIP URL, HTTP {head.status_code}"}

    try:
        total_size = int(head.headers.get("Content-Length"))
    except:
        return {"error": "Content-Length header missing or invalid"}

    # Fetch EOCD (max 22 + 65536 bytes from end)
    eocd_size = 22 + 65536
    fetch_size = min(eocd_size, total_size)
    range_start = total_size - fetch_size
    hdr = headers.copy()
    hdr["Range"] = f"bytes={range_start}-{total_size - 1}"
    resp = session.get(zip_url, headers=hdr)
    if resp.status_code not in (200, 206):
        return {"error": f"Failed to fetch EOCD, HTTP {resp.status_code}"}

    data = resp.content
    eocd_offset = data.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        return {"error": "EOCD record not found"}

    eocd = data[eocd_offset:eocd_offset + 22]
    if len(eocd) < 22:
        return {"error": "EOCD record incomplete"}

    _, _, _, _, cd_size, cd_offset, _ = struct.unpack("<HHHHIIH", eocd[4:22])

    # Fetch Central Directory
    hdr = headers.copy()
    hdr["Range"] = f"bytes={cd_offset}-{cd_offset + cd_size -1}"
    resp = session.get(zip_url, headers=hdr)
    if resp.status_code not in (200, 206):
        return {"error": f"Failed to fetch Central Directory, HTTP {resp.status_code}"}

    cd_data = resp.content
    if len(cd_data) != cd_size:
        return {"error": "Central Directory size mismatch"}

    files = []
    pos = 0
    while pos < cd_size:
        if cd_data[pos:pos+4] != b"PK\x01\x02":
            return {"error": "Invalid Central Directory header signature"}

        (
            _, _, _, gp_flag, comp_method, _, _,
            _, comp_size, uncomp_size, fname_len,
            extra_len, comment_len, _, _, _,
            local_header_offset
        ) = struct.unpack("<IHHHHHHIIIHHHHHII", cd_data[pos:pos+46])

        fname = cd_data[pos+46:pos+46+fname_len]
        filename = fname.decode(errors='replace')

        file_info = {
            "filename": filename,
            "compress_type": comp_method,
            "compressed_size": comp_size,
            "uncompressed_size": uncomp_size,
            "local_header_offset": local_header_offset,
            "gp_flag": gp_flag,
        }
        files.append(file_info)
        pos += 46 + fname_len + extra_len + comment_len

    return {"status": "ok", "files": files}

@app.route("/")
def index():
    return "Server is working!"

@app.route("/list-files", methods=["POST"])
def list_files():
    data = request.get_json(force=True)
    zip_url = data.get("url")
    if not zip_url:
        return jsonify({"error": "Missing 'url' in JSON payload"}), 400

    result = get_zip_file_list(zip_url)
    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
