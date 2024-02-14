from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel
from typing import Optional
import httpx
from fastapi.responses import RedirectResponse

app = FastAPI()

repo_data = {}  # Stores repository data indexed by repo ID
user_data = {}  # Stores user data indexed by username

class User(BaseModel):
    username: str
    email: str

class RepoData(BaseModel):
    name: str
    description: Optional[str] = None
    homepage: Optional[str] = None
    private: bool
    has_issues: Optional[bool] = False
    has_projects: Optional[bool] = False
    has_wiki: Optional[bool] = False
    is_template: Optional[bool] = True

async def github_api_request(url: str, token: str):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
    return response.json()

CLIENT_ID = "59593633e6a9145b300d"
CLIENT_SECRET = "78af32bfc701c4b7b04866e136f7858351f19aba"

@app.get("/")
def read_root():
    return {"Message": "Github Repo Management App"}

@app.get("/auth/login")
def login():
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri=http://localhost:8000/auth/callback"
        f"&scope=repo"
    )
    return RedirectResponse(url=github_auth_url)

@app.get("/auth/callback")
async def auth_callback(code: str):
    token_url = "https://github.com/login/oauth/access_token"
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            token_url,
            headers={"Accept": "application/json"},
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code
            }
        )
    access_token = token_response.json().get("access_token")
    user_data_response = await github_api_request("https://api.github.com/user", access_token)
    username = user_data_response.get("login")    
    if username in user_data:list
    raise HTTPException(status_code=400, detail="Username already exists")
    user_data[username] = {
        "email": user_data_response.get("email"),
        "repos": [],
        "token": access_token
    }
    return {"Message": "User authenticated and data retrieved successfully", "username": username}

@app.post("/user/{username}/add_repo")
async def add_repository(username: str, repo_data: RepoData):
    if username not in user_data or "token" not in user_data[username]:
        raise HTTPException(status_code=401, detail="User not authenticated or token missing")
    token = user_data[username]["token"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = repo_data.dict()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.github.com/user/repos",
            headers=headers,
            json=data
        )
    if response.status_code != 201:
        raise HTTPException(status_code=response.status_code, detail=response.text)
    response_data = response.json()
    repo_id = response_data.get("id")
    user_data[username]["repos"].append(repo_id)
    return {"Message": "Repository added successfully", "repo_info": response_data}

@app.get("/repo/{repo_id}")
async def get_repository(repo_id: str, username: str = Query(...)):
    if username not in user_data or "token" not in user_data[username]:
        raise HTTPException(status_code=401, detail="User not authenticated or token missing")
    token = user_data[username]["token"]
    repo_info = await github_api_request(f"https://api.github.com/repos/{username}/{repo_id}", token)
    return repo_info
@app.post("/user/{username}/add_webhook")
async def add_webhook(username: str, repo_name: str = Query(...)):
 # Check if the user is authenticated
 if username not in user_data or "token" not in user_data[username]:
    raise HTTPException(status_code=401, detail="User not authenticated or token missing")
 # Retrieve the user's token
 token = user_data[username]["token"]
 # Define the URL where your application will receive webhook events
 webhook_url = "https://96fc-2601-403-c300-172d-b45a-d9ab-92e9-25.ngrok-free.app/webhook_receiver" # Replace with your server's webhook URL
 # Set up the configuration for the webhook
 webhook_config = {
 "url": webhook_url,
 "content_type": "json"
 }
 # Data to be sent to GitHub API for creating the webhook
 data = {
 "name": "web",
 "active": True,
 "events": ["push", "pull_request", "issue_comment"],
 "config": webhook_config
 }
 # Set headers for the request
 headers = {
 "Authorization": f"Bearer {token}",
 "Accept": "application/vnd.github.v3+json"
 }
 # Make a POST request to the GitHub API to create the webhook
 async with httpx.AsyncClient() as client: response = await client.post(

f"https://api.github.com/repos/{username}/{repo_name}/hooks",
 headers=headers,
 json=data
 )
 # Check the response status
 if response.status_code != 201:
     raise HTTPException(status_code=response.status_code,
detail=response.text)
 # Return a success message and webhook details
 return {"message": "Webhook added successfully", "webhook_info":
response.json()}

@app.post("/webhook_receiver")
async def webhook_receiver(request: Request):
 # Extract the JSON payload from the request
 payload = await request.json()
 # Process the webhook payload as needed
 print("Webhook event received:", payload)
 # Return a response
 return {"message": "Webhook event received"}