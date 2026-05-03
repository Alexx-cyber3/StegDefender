from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
import shutil
import os
import uuid
import sys
import io

# Add project root to sys.path
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(root_path)

try:
    from stegdefender.core.engine import ForensicEngine
    from stegdefender.core.cracker import Cracker
    from stegdefender.core.crypto import CryptoManager
    from stegdefender.core.extractor import StegoExtractor
    from stegdefender.utils.pdf_reporter import ReportGenerator
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

app = FastAPI(title="StegDefender API")

# Simple in-memory store for reports (ID -> Analysis Result)
analysis_cache = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.path.join(root_path, "web", "uploads")
REPORTS_DIR = os.path.join(root_path, "web", "reports")
CLIENT_DIR = os.path.join(root_path, "web", "client")
STATIC_DIR = os.path.join(CLIENT_DIR, "static")
EXTRACTED_DIR = os.path.join(root_path, "stegdefender", "extracted_data")
HISTORY_DIR = os.path.join(root_path, "web", "history")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(EXTRACTED_DIR, exist_ok=True)
os.makedirs(HISTORY_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

import json
from datetime import datetime

def save_history(data):
    file_id = data['id']
    history_path = os.path.join(HISTORY_DIR, f"{file_id}.json")
    # Add timestamp for history sorting
    data['timestamp'] = datetime.now().isoformat()
    with open(history_path, 'w') as f:
        json.dump(data, f)

def load_history():
    history_list = []
    if not os.path.exists(HISTORY_DIR):
        return []
    for filename in os.listdir(HISTORY_DIR):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(HISTORY_DIR, filename), 'r') as f:
                    data = json.load(f)
                    # We only need metadata for the list view to save bandwidth
                    history_list.append({
                        "id": data['id'],
                        "filename": data['filename'],
                        "timestamp": data.get('timestamp', ''),
                        "risk_score": data.get('risk_score', 0)
                    })
            except:
                pass
    # Sort by timestamp descending
    return sorted(history_list, key=lambda x: x['timestamp'], reverse=True)

@app.get("/history")
async def get_history():
    return load_history()

@app.get("/history/{file_id}")
async def get_history_detail(file_id: str):
    history_path = os.path.join(HISTORY_DIR, f"{file_id}.json")
    if os.path.exists(history_path):
        with open(history_path, 'r') as f:
            data = json.load(f)
            # Restore to cache if not there
            if file_id not in analysis_cache:
                analysis_cache[file_id] = data
            return data
    raise HTTPException(status_code=404, detail="History not found")

@app.get("/extracted/{path:path}")
async def get_extracted_file(path: str):
    # Ensure we are looking in the absolute extracted directory
    abs_extracted_dir = os.path.abspath(EXTRACTED_DIR)
    full_path = os.path.abspath(os.path.join(abs_extracted_dir, path))
    
    # Security check: ensure the path is within the extracted directory
    if not full_path.startswith(abs_extracted_dir):
         raise HTTPException(status_code=403, detail="Access denied")

    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    filename = os.path.basename(full_path)
    # Use 'inline' instead of 'attachment' so the browser can display the file if it supports the format
    return FileResponse(
        full_path, 
        headers={"Content-Disposition": f"inline; filename=\"{filename}\""}
    )

def enrich_artifacts_with_urls(node, parent_artifact_url=None):
    """
    Recursively adds a 'url' field to artifacts and nodes based on their file path.
    """
    if not node:
        return

    # If this is a nested node, it might have been passed a URL from its parent's artifact list
    if parent_artifact_url:
        node["url"] = parent_artifact_url

    # Check finding's artifacts
    if "findings" in node and "artifacts" in node["findings"]:
        extracted_abs = os.path.abspath(EXTRACTED_DIR)
        for artifact in node["findings"]["artifacts"]:
            # Ensure we are comparing absolute paths
            full_path = os.path.abspath(artifact["path"])
            
            if full_path.startswith(extracted_abs):
                rel_path = os.path.relpath(full_path, extracted_abs)
                rel_path = rel_path.replace("\\", "/")
                artifact["url"] = f"/extracted/{rel_path}"

    # Recurse
    if "nested" in node:
        for child in node["nested"]:
            # Find the artifact URL in the current node that corresponds to this nested analysis
            artifact_name = child.get("artifact_name")
            this_artifact_url = None
            if artifact_name and "findings" in node and "artifacts" in node["findings"]:
                for art in node["findings"]["artifacts"]:
                    if art["name"] == artifact_name:
                        this_artifact_url = art.get("url")
                        break
            
            enrich_artifacts_with_urls(child["analysis"], this_artifact_url)

@app.get("/")
async def read_index():
    index_path = os.path.join(CLIENT_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "Frontend index.html not found"}

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1]
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}{file_ext}")
    
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        engine = ForensicEngine(max_depth=3)
        results_tree = engine.run(temp_path)
        global_score = engine.calculate_risk_score(results_tree)
        
        # Add URLs for frontend access
        enrich_artifacts_with_urls(results_tree)

        response_data = {
            "id": file_id,
            "filename": file.filename,
            "file_path": temp_path,
            "results": results_tree,
            "risk_score": global_score
        }
        
        # Save to history
        save_history(response_data)
        
        analysis_cache[file_id] = response_data
        
        return response_data
    except Exception as e:
        print(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/crack")
async def crack_file(file_id: str = Form(...), wordlist: UploadFile = File(None)):
    data = analysis_cache.get(file_id)
    if not data:
        raise HTTPException(status_code=404, detail="File analysis not found. Re-upload.")
        
    target_path = data['file_path']
    mime = data['results']['info']['mime']
    
    custom_passwords = None
    if wordlist:
        content = await wordlist.read()
        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError:
            text = content.decode('latin-1')
            
        custom_passwords = [line.strip() for line in text.splitlines() if line.strip()]
    
    cracker = Cracker()
    result = cracker.crack(target_path, mime, custom_passwords=custom_passwords)
    
    return result

@app.get("/report/{file_id}")
async def generate_report(file_id: str):
    data = analysis_cache.get(file_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis data not found")
        
    pdf_filename = f"report_{file_id}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)
    
    reporter = ReportGenerator()
    reporter.generate(data['results'], pdf_path)
    
    return FileResponse(pdf_path, media_type='application/pdf', filename=pdf_filename)

# --- Crypto Endpoints ---

async def get_input_data(text: str, file: UploadFile):
    if file:
        return await file.read()
    if text:
        return text.encode('utf-8')
    raise HTTPException(status_code=400, detail="No input data provided (text or file)")

def crypto_response(result_data: bytes, is_file: bool, filename="result.bin"):
    if is_file:
        return StreamingResponse(
            io.BytesIO(result_data),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    else:
        try:
            return {"result": result_data.decode('utf-8')}
        except:
            return {"result": result_data.hex()}

@app.post("/crypto/encrypt")
async def crypto_encrypt(
    algorithm: str = Form(...), 
    password: str = Form(...), 
    text: str = Form(None), 
    file: UploadFile = File(None)
):
    data = await get_input_data(text, file)
    try:
        if algorithm == 'aes':
            result = CryptoManager.encrypt_aes(data, password)
        elif algorithm == 'chacha':
            result = CryptoManager.encrypt_chacha(data, password)
        else:
            raise HTTPException(status_code=400, detail="Unsupported algorithm")
        
        return crypto_response(result.encode(), file is not None, "encrypted.txt")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/crypto/decrypt")
async def crypto_decrypt(
    algorithm: str = Form(...), 
    password: str = Form(...), 
    text: str = Form(None), 
    file: UploadFile = File(None),
    stego_mode: bool = Form(False),
    stego_password: str = Form(None)
):
    raw_input = await get_input_data(text, file)
    
    try:
        # Auto-detect or explicit Stego Mode
        is_media_file = False
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext in ['.jpg', '.jpeg', '.bmp', '.wav', '.au', '.png']:
                is_media_file = True

        if stego_mode or is_media_file:
            # We need a file on disk for Steghide/Extractor
            temp_extract_path = os.path.join(UPLOAD_DIR, f"temp_extract_{uuid.uuid4()}")
            # If valid extension, preserve it for tools that rely on it (like steghide)
            if file and file.filename:
                 temp_extract_path += os.path.splitext(file.filename)[1]

            with open(temp_extract_path, "wb") as f:
                f.write(raw_input)
            
            try:
                extracted_data = None
                
                # Strategy 1: Explicit Stego Password
                if stego_password:
                    extracted_data = StegoExtractor.extract(temp_extract_path, stego_password)
                
                # Strategy 2: Reuse Decryption Password (common user behavior)
                if not extracted_data and password:
                    extracted_data = StegoExtractor.extract(temp_extract_path, password)
                
                # Strategy 3: Empty Password
                if not extracted_data:
                    extracted_data = StegoExtractor.extract(temp_extract_path, "")

                # If successful, replace raw_input
                if extracted_data:
                    raw_input = extracted_data
                elif stego_mode:
                    # If user explicitly asked for stego mode and it failed, raise error
                    raise HTTPException(status_code=400, detail="Stego Extraction failed: No hidden data found or incorrect stego password.")
                # If auto-detect failed, we just fall back to treating the file as raw ciphertext (will likely fail decryption, but correct flow)
            finally:
                if os.path.exists(temp_extract_path):
                    os.remove(temp_extract_path)

        token = raw_input.decode('utf-8').strip()
        
        if algorithm == 'aes':
            plaintext = CryptoManager.decrypt_aes(token, password)
        elif algorithm == 'chacha':
            plaintext = CryptoManager.decrypt_chacha(token, password)
        else:
            raise HTTPException(status_code=400, detail="Unsupported algorithm")
            
        return crypto_response(plaintext, file is not None or stego_mode or is_media_file, "decrypted_file")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/crypto/rsa/keys")
async def generate_rsa_keys():
    try:
        priv, pub = CryptoManager.generate_rsa_keys()
        return {"private_key": priv, "public_key": pub}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/crypto/rsa/encrypt")
async def rsa_encrypt(
    public_key: str = Form(...), 
    text: str = Form(None), 
    file: UploadFile = File(None)
):
    data = await get_input_data(text, file)
    try:
        result = CryptoManager.encrypt_rsa(data, public_key)
        return crypto_response(result.encode(), file is not None, "rsa_encrypted.txt")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/crypto/rsa/decrypt")
async def rsa_decrypt(
    private_key: str = Form(...), 
    text: str = Form(None), 
    file: UploadFile = File(None)
):
    raw_input = await get_input_data(text, file)
    try:
        token = raw_input.decode('utf-8').strip()
        plaintext = CryptoManager.decrypt_rsa(token, private_key)
        return crypto_response(plaintext, file is not None, "rsa_decrypted_file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/crypto/hash")
async def calculate_hash(text: str = Form(None), file: UploadFile = File(None)):
    data = await get_input_data(text, file)
    try:
        result = CryptoManager.hash_sha256(data)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")