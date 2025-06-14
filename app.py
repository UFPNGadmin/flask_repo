from flask import Flask, request, render_template_string, jsonify, send_file, abort
import requests
import struct
import io
import zlib
import os
import tempfile

app = Flask(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122 Safari/537.36"

# HTML template with minimal UI
HTML_TEMPLATE = """
<!doctype html>
<title>Remote ZIP Partial Downloader</title>
<h1>Remote ZIP Partial Downloader</h1>
<form id="loadForm">
    ZIP URL: <input type="text" name="url" size="80" required><br><br>
    Cookies (optional): <input type="text" name="cookies" size="80"><br><br>
    <label><input type="checkbox" name="ua"> Impersonate browser (User-Agent)</label><br><br>
    <button type="submit">Load ZIP Contents</button>
</form>

<div id="status"></div>
<ul id="fileList"></ul>

<form id="downloadForm" style="display:none;">
    <h3>Select files to download:</h3>
    <div id="filesCheckboxes"></div><br>
    <button type="submit">Download Selected Files as ZIP</button>
</form>

<script>
const loadForm = document.getElementById('loadForm');
const downloadForm = document.getElementById('downloadForm');
const statusDiv = document.getElementById('status');
const fileListUl = document.getElementById('fileList');
const filesCheckboxesDiv = document.getElementById('filesCheckboxes');

loadForm.addEventListener('submit', async e => {
    e.preventDefault();
    statusDiv.textContent = "Loading ZIP contents...";
    fileListUl.innerHTML = "";
    filesCheckboxesDiv.innerHTML = "";
    downloadForm.style.display = "none";

    const formData = new FormData(loadForm);
    const data = Object.fromEntries(formData.entries());
    data.ua = formData.get('ua') === 'on' || formData.get('ua') === 'true' || formData.get('ua') === 'on';

    const res = await fetch('/list_files', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    });
    if (!res.ok) {
        statusDiv.textContent = "Error loading ZIP contents.";
        return;
    }
    const json = await res.json();
    if (json.error) {
        statusDiv.textContent = "Error: " + json.error;
        return;
    }
    statusDiv.textContent = "ZIP contents loaded.";
    json.files.forEach((f, i) => {
        const li = document.createElement('li');
        li.textContent = `${f.filename}${f.encrypted ? " [ENCRYPTED]" : ""} | Compressed: ${f.comp_size} | Uncompressed: ${f.uncomp_size}`;
        fileListUl.appendChild(li);

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.name = 'files';
        checkbox.value = i;
        filesCheckboxesDiv.appendChild(checkbox);

        const label = document.createElement('label');
        label.textContent = f.filename;
        label.style.marginRight = "20px";
        filesCheckboxesDiv.appendChild(label);
    });
    downloadForm.style.display = "block";
});

downloadForm.addEventListener('submit', async e => {
    e.preventDefault();
    const formData = new FormData(loadForm);
    const downloadData = Object.fromEntries(formData.entries());
    downloadData.ua = formData.get('ua') === 'on' || formData.get('ua') === 'true' || formData.get('ua') === 'on';

    const checkedBoxes = Array.from(downloadForm.querySelectorAll('input[name="files"]:checked'));
    if (checkedBoxes.length === 0) {
        alert("Select at least one file to download.");
        return;
    }
    downloadData.files = checkedBoxes.map(cb => parseInt(cb.value));

    statusDiv.textContent = "Preparing download...";

    // POST to download endpoint, receive zip file stream
    const res = await fetch('/download_files', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(downloadData)
    });
    if (!res.ok) {
        statusDiv.textContent = "Download failed.";
        return;
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "selected_files.zip";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    statusDiv.textContent = "Download started.";
});
</script>
"""

def get_headers(cookies, use_ua):
    headers = {}
    if use_ua:
        headers['User-Agent'] = USER_AGENT
    if cookies:
        headers['Cookie'] = cookies
    return headers

def parse_central_directory(cd_data):
    files = []
    pos = 0
    size = len(cd_data)
    while pos < size:
        if cd_data[pos:pos+4] != b"PK\x01\x02":
            break
        try:
            (
                _, _, _, gp_flag, comp_method, _, _,
                _, comp_size, uncomp_size, fname_len,
                extra_len, comment_len, _, _, _,
                local_header_offset
            ) = struct.unpack("<IHHHHHHIIIHHHHHII", cd_data[pos:pos+46])
        except struct.error:
            break

        fname = cd_data[pos+46:pos+46+fname_len]
        filename = fname.decode(errors='replace')
        files.append({
            "filename": filename,
            "compressed_size": comp_size,
            "uncompressed_size": uncomp_size,
            "compress_type": comp_method,
            "local_header_offset": local_header_offset,
            "encrypted": (gp_flag & 0x1) != 0
        })
        pos += 46 + fname_len + extra_len + comment_len
    return files

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/list_files', methods=['POST'])
def list_files():
    data = request.get_json()
    url = data.get('url')
    cookies = data.get('cookies')
    use_ua = data.get('ua', False)

    if not url:
        return jsonify({"error": "Missing ZIP URL"}), 400

    try:
        # Get content length
        head = requests.head(url, allow_redirects=True, headers=get_headers(cookies, use_ua))
        if head.status_code != 200:
            return jsonify({"error": f"Failed to access file: HTTP {head.status_code}"}), 400
        total_size = int(head.headers.get("Content-Length", 0))
        if total_size == 0:
            return jsonify({"error": "Content-Length missing or zero"}), 400

        eocd_size = 22 + 65536
        fetch_size = min(eocd_size, total_size)
        range_start = total_size - fetch_size
        headers = get_headers(cookies, use_ua)
        headers["Range"] = f"bytes={range_start}-{total_size - 1}"
        resp = requests.get(url, headers=headers)
        if resp.status_code not in (200, 206):
            return jsonify({"error": f"Failed to get EOCD: HTTP {resp.status_code}"}), 400

        data = resp.content
        eocd_offset = data.rfind(b"PK\x05\x06")
        if eocd_offset < 0:
            return jsonify({"error": "EOCD record not found"}), 400

        eocd = data[eocd_offset:eocd_offset + 22]
        if len(eocd) < 22:
            return jsonify({"error": "Incomplete EOCD record"}), 400

        _, _, _, _, cd_size, cd_offset, _ = struct.unpack("<HHHHIIH", eocd[4:22])

        headers = get_headers(cookies, use_ua)
        headers["Range"] = f"bytes={cd_offset}-{cd_offset + cd_size - 1}"
        resp = requests.get(url, headers=headers)
        if resp.status_code not in (200, 206):
            return jsonify({"error": f"Failed to get Central Directory: HTTP {resp.status_code}"}), 400

        cd_data = resp.content
        if len(cd_data) != cd_size:
            return jsonify({"error": "Central Directory size mismatch"}), 400

        files = parse_central_directory(cd_data)
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/download_files', methods=['POST'])
def download_files():
    data = request.get_json()
    url = data.get('url')
    cookies = data.get('cookies')
    use_ua = data.get('ua', False)
    selected_indices = data.get('files', [])

    if not url or not selected_indices:
        return jsonify({"error": "Missing URL or files to download"}), 400

    # Re-load file list to get file info
    # (In a real app, you'd cache this after listing for better perf)
    try:
        head = requests.head(url, allow_redirects=True, headers=get_headers(cookies, use_ua))
        total_size = int(head.headers.get("Content-Length", 0))
        eocd_size = 22 + 65536
        fetch_size = min(eocd_size, total_size)
        range_start = total_size - fetch_size
        headers = get_headers(cookies, use_ua)
        headers["Range"] = f"bytes={range_start}-{total_size - 1}"
        resp = requests.get(url, headers=headers)
        data_resp = resp.content
        eocd_offset = data_resp.rfind(b"PK\x05\x06")
        eocd = data_resp[eocd_offset:eocd_offset + 22]
        _, _, _, _, cd_size, cd_offset, _ = struct.unpack("<HHHHIIH", eocd[4:22])
        headers["Range"] = f"bytes={cd_offset}-{cd_offset + cd_size - 1}"
        cd_resp = requests.get(url, headers=headers)
        cd_data = cd_resp.content
        files = parse_central_directory(cd_data)
    except Exception as e:
        return jsonify({"error": "Failed to reload file list: " + str(e)}), 500

    # Validate selected indices
    try:
        selected_files = [files[i] for i in selected_indices]
    except Exception:
        return jsonify({"error": "Invalid file indices"}), 400

    # Create an in-memory ZIP with selected files downloaded and decompressed
    memory_zip = io.BytesIO()
    import zipfile
    with zipfile.ZipFile(memory_zip, "w", compression=zipfile.ZIP_DEFLATED) as outzip:
        session = requests.Session()
        for f in selected_files:
            try:
                if f["encrypted"]:
                    # For encrypted files, just download raw as partial ZIP file (no decompression)
                    lh_offset = f["local_header_offset"]
                    headers = get_headers(cookies, use_ua)
                    headers["Range"] = f"bytes={lh_offset}-{lh_offset+30}"
                    resp = session.get(url, headers=headers)
                    lh_data = resp.content
                    fname_len, extra_len = struct.unpack("<HH", lh_data[26:30])
                    header_end = lh_offset + 30 + fname_len + extra_len - 1

                    headers["Range"] = f"bytes={lh_offset}-{header_end}"
                    full_header = session.get(url, headers=headers).content

                    data_start = header_end + 1
                    data_end = data_start + f["compressed_size"] - 1
                    headers["Range"] = f"bytes={data_start}-{data_end}"
                    encrypted_data = session.get(url, headers=headers).content

                    # Write raw encrypted file into zipfile under its filename
                    outzip.writestr(f["filename"], full_header + encrypted_data)
                    continue

                # Download local file header to find compressed data start
                lh_offset = f["local_header_offset"]
                headers = get_headers(cookies, use_ua)
                headers["Range"] = f"bytes={lh_offset}-{lh_offset+30}"
                resp = session.get(url, headers=headers)
                lh_data = resp.content
                fname_len, extra_len = struct.unpack("<HH", lh_data[26:30])
                data_start = lh_offset + 30 + fname_len + extra_len
                data_end = data_start + f["compressed_size"] - 1

                # Download compressed data
                headers["Range"] = f"bytes={data_start}-{data_end}"
                resp = session.get(url, headers=headers)
                compressed_data = resp.content

                # Decompress if needed
                if f["compress_type"] == 0:
                    file_data = compressed_data
                elif f["compress_type"] == 8:
                    decompress_obj = zlib.decompressobj(-zlib.MAX_WBITS)
                    file_data = decompress_obj.decompress(compressed_data)
                    file_data += decompress_obj.flush()
                else:
                    # Unknown compression, store raw compressed data
                    file_data = compressed_data

                outzip.writestr(f["filename"], file_data)
            except Exception as e:
                # On error, skip file
                continue

    memory_zip.seek(0)
    return send_file(memory_zip, mimetype='application/zip', as_attachment=True, download_name="selected_files.zip")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
