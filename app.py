from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import json
from typing import Optional, Dict, Any
from scan_suggessted_fixes import run_security_scan 

app = FastAPI()

class ScanRequest(BaseModel):
    target: Optional[str] = None
    scan_type: Optional[str] = "basic"
    scan_results: Dict[str, Any]  # ZAP or scanner JSON findings


@app.post("/scan")
def start_scan(req: ScanRequest):
    try:
        # Path to your project source code directory
        project_dir = "../renewable-energy-app-main"
        abs_project_dir = os.path.abspath(project_dir)
        # Run the custom security scan logic
        result = run_security_scan(req.target, req.scan_type, project_dir, req.scan_results)
        cleaned_result = {}

        for severity, issues in result.items():
            cleaned_issues = []
            for item in issues:
                file_field = item.get("file", "").strip()

                # Use only the first file path if multiple are present
                first_file = file_field.split(";")[0].strip()

                # Check if it looks like a real file path
                if "/" in first_file and "." in os.path.basename(first_file):
                    try:
                        abs_file_path = os.path.abspath(first_file)
                        relative_path = os.path.relpath(abs_file_path, abs_project_dir)
                        item["file"] = f"../{relative_path}"
                        cleaned_issues.append(item)
                    except Exception:
                        continue  # Skip if path resolution fails
                else:
                    continue  # Skip if it doesn't look like a real file path

            cleaned_result[severity] = cleaned_issues

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
