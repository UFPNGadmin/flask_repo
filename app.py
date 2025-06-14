import struct
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_headers(cookie="", user_agent=True):
    headers = {}
    if user_agent:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122 Safari/537.36"
    if cookie:
        headers["Cookie"] = cookie
    return headers

@app.route("/")
def index():
    return "Server is working!"

@app.route("/list-files", methods=["POST"])
def list_files():
    data = request.json
    zip_url = data.get("url")
    cookies = data.get("cookies", "")
    
    if not zip_url:
        return jsonify({"status": "error", "message": "Missing URL"}), 400

    session = requests.Session()

    try:
        head = session.head(zip_url, allow_redirects=True, headers=get_headers(cookies))
        if head.status_code != 200:
            return jsonify({"status": "error", "message": f"HEAD request failed with status {head.status_code}"}), 400

        total_size = int(head.headers.get("Content-Length", 0))
        if total_size == 0:
            return jsonify({"status": "error", "message": "Content-Length not provided or zero"}), 400

        # Fetch EOCD region (end of central directory)
        eocd_search_size = min(22 + 65536, total_size)
        range_start = total_size - eocd_search_size
        headers = get_headers(cookies)
        headers["Range"] = f"bytes={range_start}-{total_size - 1}"
        resp = session.get(zip_url, headers=headers)
        if resp.status_code not in (200, 206):
            return jsonify({"status": "error", "message": f"Failed to get EOCD region, status {resp.status_code}"}), 400

        data = resp.content
        eocd_offset = data.rfind(b"PK\x05\x06")
        if eocd_offset < 0:
            return jsonify({"status": "error", "message": "EOCD signature not found"}), 400

        if len(data) < eocd_offset + 22:
            return jsonify({"status": "error", "message": "Incomplete EOCD record"}), 400

        eocd = data[eocd_offset:eocd_offset + 22]
        # Unpack EOCD structure: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT (section 4.3.7)
        # Format: <HHHHIIH (4+2+2+2+2+4+4+2 bytes total 22)
        # But we unpack <HHHHIIH for 18 bytes after first 4 (signature)
        _, _, _, _, cd_size, cd_offset, _ = struct.unpack("<HHHHIIH", eocd[4:22])

        # Fetch Central Directory
        headers = get_headers(cookies)
        headers["Range"] = f"bytes={cd_offset}-{cd_offset + cd_size - 1}"
        resp = session.get(zip_url, headers=headers)
        if resp.status_code not in (200, 206):
            return jsonify({"status": "error", "message": f"Failed to get Central Directory, status {resp.status_code}"}), 400

        cd_data = resp.content
        if len(cd_data) != cd_size:
            return jsonify({"status": "error", "message": "Central Directory size mismatch"}), 400

        files = []
        pos = 0
        while pos < cd_size:
            if cd_data[pos:pos+4] != b"PK\x01\x02":
                return jsonify({"status": "error", "message": "Invalid Central Directory header signature"}), 400

            (
                _, _, _, gp_flag, comp_method, _, _,
                _, comp_size, uncomp_size, fname_len,
                extra_len, comment_len, _, _, _,
                local_header_offset
            ) = struct.unpack("<IHHHHHHIIIHHHHHII", cd_data[pos:pos+46])

            fname = cd_data[pos+46:pos+46+fname_len]
            filename = fname.decode(errors='replace')

            files.append({
                "filename": filename,
                "compress_type": comp_method,
                "compressed_size": comp_size,
                "uncompressed_size": uncomp_size,
                "local_header_offset": local_header_offset,
                "gp_flag": gp_flag,
            })
            pos += 46 + fname_len + extra_len + comment_len

        return jsonify({"status": "ok", "files": files})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
