from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import struct
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains by default

def parse_central_directory(zip_url, headers):
    # HEAD request to get total content length
    head = requests.head(zip_url, headers=headers, allow_redirects=True)
    if head.status_code != 200:
        return None, f"HEAD request failed with status {head.status_code}"

    try:
        total_size = int(head.headers.get("Content-Length"))
    except:
        return None, "Failed to get Content-Length from headers"

    # Fetch EOCD (End of central directory) - last 64 KB max or less
    eocd_search_size = min(65536 + 22, total_size)
    range_start = total_size - eocd_search_size
    hdrs = headers.copy()
    hdrs["Range"] = f"bytes={range_start}-{total_size - 1}"
    resp = requests.get(zip_url, headers=hdrs)
    if resp.status_code not in (200, 206):
        return None, f"Failed to get EOCD: HTTP {resp.status_code}"

    data = resp.content
    eocd_offset = data.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        return None, "EOCD record not found in ZIP"

    eocd = data[eocd_offset:eocd_offset + 22]
    if len(eocd) < 22:
        return None, "Incomplete EOCD record"

    # Parse EOCD
    # Structure: <HHHHIIH>
    _, _, _, _, cd_size, cd_offset, _ = struct.unpack("<HHHHIIH", eocd[4:22])

    # Fetch central directory
    hdrs = headers.copy()
    hdrs["Range"] = f"bytes={cd_offset}-{cd_offset + cd_size - 1}"
    cd_resp = requests.get(zip_url, headers=hdrs)
    if cd_resp.status_code not in (200, 206):
        return None, f"Failed to get Central Directory: HTTP {cd_resp.status_code}"

    cd_data = cd_resp.content
    if len(cd_data) != cd_size:
        return None, "Central Directory size mismatch"

    files = []
    pos = 0
    while pos < cd_size:
        if cd_data[pos:pos + 4] != b"PK\x01\x02":
            return None, "Invalid Central Directory header signature"

        (
            _, _, _, gp_flag, comp_method, _, _,
            _, comp_size, uncomp_size, fname_len,
            extra_len, comment_len, _, _, _,
            local_header_offset
        ) = struct.unpack("<IHHHHHHIIIHHHHHII", cd_data[pos:pos + 46])

        fname = cd_data[pos + 46:pos + 46 + fname_len]
        filename = fname.decode(errors="replace")

        files.append({
            "filename": filename,
            "compress_type": comp_method,
            "compressed_size": comp_size,
            "uncompressed_size": uncomp_size,
            "local_header_offset": local_header_offset,
            "encrypted": bool(gp_flag & 0x1),
        })

        pos += 46 + fname_len + extra_len + comment_len

    return files, None

@app.route("/")
def index():
    return "Server is working!"

@app.route("/list-files", methods=["POST"])
def list_files():
    data = request.get_json(force=True)
    zip_url = data.get("url")
    if not zip_url:
        return jsonify({"status": "error", "message": "Missing 'url' in request JSON"}), 400

    headers = {}
    cookies = data.get("cookies")
    if cookies:
        headers["Cookie"] = cookies
    if data.get("use_ua", False):
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122 Safari/537.36"

    files, error = parse_central_directory(zip_url, headers)
    if error:
        return jsonify({"status": "error", "message": error}), 400

    return jsonify({"status": "ok", "files": files})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
