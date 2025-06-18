from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from scan_suggessted_fixes import read_project_files, run_security_scan
from typing import Optional

app = FastAPI()

class ScanRequest(BaseModel):
    target: Optional[str] = None
    scan_type: str = "basic"
    report: str
    project_path: str = "../renewable-energy-app-main"

@app.post("/scan")
def start_scan(req: ScanRequest):
    try:
        project_code = read_project_files(os.path.abspath(req.project_path))
        result = run_security_scan(req.target, req.scan_type, project_code, req.report)
        return result
    except Exception as e:
        return {"error": str(e)}
