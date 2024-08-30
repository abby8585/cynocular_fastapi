from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import requests
import os
from werkzeug.utils import secure_filename
from langchain import OpenAI, LLMChain
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Mount the static directory to serve CSS, JS, images, etc.
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Environment variables for API keys
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
VT_API_KEY = os.getenv('VT_API_KEY')
VT_API_URL = 'https://www.virustotal.com/api/v3'

# Initialize LangChain components
llm = OpenAI(api_key=OPENAI_API_KEY, model_name="gpt-4")
prompt_template = PromptTemplate(
    input_variables=["input_text"],
    template="Provide a cybersecurity-related summary for the following input:\n\n{input_text}"
)
gpt_chain = LLMChain(prompt=prompt_template, llm=llm)

def summarize_with_gpt(prompt: str) -> str:
    try:
        result = gpt_chain.run(input_text=prompt)
        return result
    except Exception as e:
        return f"Error summarizing with GPT: {e}"

class VTRequest(BaseModel):
    fileHash: str = None
    url: str = None
    ip: str = None
    domain: str = None

@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/vt/scan")
async def vt_scan(request: VTRequest):
    headers = {'x-apikey': VT_API_KEY}
    endpoint = None

    if request.fileHash:
        endpoint = f'{VT_API_URL}/files/{request.fileHash}'
    elif request.url:
        endpoint = f'{VT_API_URL}/urls/{request.url}'
    elif request.ip:
        endpoint = f'{VT_API_URL}/ips/{request.ip}'
    elif request.domain:
        endpoint = f'{VT_API_URL}/domains/{request.domain}'
    else:
        raise HTTPException(status_code=400, detail="No valid parameter provided")

    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        result = response.json()
        summary = summarize_with_gpt(str(result))
        return JSONResponse(content={"summary": summary})
    except requests.exceptions.RequestException as e:
        return JSONResponse(content={"error": f"Error fetching VirusTotal scan result: {e}"}, status_code=500)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    if file.filename == '':
        raise HTTPException(status_code=400, detail="No selected file")

    filename = secure_filename(file.filename)
    file_path = os.path.join('uploads', filename)
    
    if not os.path.exists('uploads'):
        os.makedirs('uploads')

    try:
        with open(file_path, 'wb') as f:
            f.write(await file.read())
        
        # Send file to VirusTotal for scanning
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f)}
            headers = {'x-apikey': VT_API_KEY}
            response = requests.post(f'{VT_API_URL}/files', headers=headers, files=files)
            response.raise_for_status()
            result = response.json()

        # Summarize VirusTotal result with GPT-4
        prompt = f"File Scan Result:\n{result}\n\nProvide a cybersecurity-related analysis and summary."
        file_summary = summarize_with_gpt(prompt)

        return JSONResponse(content={"summary": file_summary})
    except requests.exceptions.RequestException as e:
        return JSONResponse(content={"error": f"Error uploading and scanning file: {e}"}, status_code=500)
    except Exception as e:
        return JSONResponse(content={"error": f"Error processing file: {e}"}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
