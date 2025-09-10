import os.path
import base64
from bs4 import BeautifulSoup
import re, json
import google.generativeai as genai
from dotenv import load_dotenv
import gspread

# Load environment variables
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Google API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as UserCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# === CONFIG ===
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
SHEETS_SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SERVICE_ACCOUNT_FILE = 'service_account.json'   # Path to service account JSON
SHEET_ID = "1z8z8tq-AkNXhnRjtu9e_BtJPP5dlVyRwmVqdhUBBRNs"  # Spreadsheet ID from URL

# === Google Sheets Auth (Service Account) ===
creds_sheets = ServiceAccountCredentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE,
    scopes=SHEETS_SCOPES
)
gc = gspread.authorize(creds_sheets)
sheet = gc.open_by_key(SHEET_ID).sheet1


# === Utility Functions ===

def get_last_processed_id():
    if os.path.exists("last_id.txt"):
        with open("last_id.txt", "r") as f:
            return f.read().strip()
    return None

def save_last_processed_id(msg_id):
    with open("last_id.txt", "w") as f:
        f.write(msg_id)

def decode_base64url(data):
    """Decode Gmail API's base64url-encoded string into text"""
    return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')

def flatten_field(value):
    """Convert lists/dicts into a clean string for Sheets"""
    if isinstance(value, list):
        return "; ".join(flatten_field(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    return str(value) if value is not None else ""



def extract_clean_body(payload):
    """
    Recursively extract and clean the first text/plain or text/html body.
    Prefers text/plain, falls back to cleaned HTML.
    """
    if 'body' in payload and 'data' in payload['body']:
        raw_text = decode_base64url(payload['body']['data'])
        if payload.get("mimeType") == "text/plain":
            return raw_text.strip()
        elif payload.get("mimeType") == "text/html":
            soup = BeautifulSoup(raw_text, "html.parser")
            return soup.get_text(separator="\n", strip=True)

    if 'parts' in payload:
        for part in payload['parts']:
            body_text = extract_clean_body(part)
            if body_text:
                return body_text
    return None


def postprocess_email_text(text):
    """Clean email body for LLM consumption."""
    if not text:
        return ""
    clean = re.sub(r'\n\s*\n+', '\n\n', text)  # collapse big gaps
    clean = re.sub(r'[ \t]+', ' ', clean)      # collapse spaces
    for marker in ["Warm regards", "Disclaimer:"]:
        idx = clean.lower().find(marker.lower())
        if idx != -1:
            clean = clean[:idx].strip()
            break
    return clean


def company_exists(sheet, company_name):
    """Check if company already exists in column B"""
    all_companies = sheet.col_values(1)
    return company_name in all_companies


def append_to_sheet(sheet, data, email_link):
    """Append parsed data to sheet if relevant & not duplicate"""
    if not data:
        return
    if data.get("is_relevant") != "yes":
        print("Skipped: Not relevant")
        return
    if company_exists(sheet, data.get("company", "")):
        print("Skipped: Company already exists")
        return

    row = [
        flatten_field(data.get("company")),
        flatten_field(data.get("date_of_visit")),
        flatten_field(data.get("eligibility")),
        flatten_field(data.get("ctc")),
        flatten_field(data.get("stipend")),
        flatten_field(data.get("registration_deadline")),
        flatten_field(data.get("job_designation")),
        flatten_field(data.get("register_link")),
        email_link
    ]
    sheet.append_row(row)
    print(f"Pushed to sheet: {data.get('company')}")


def extract_email_data(subject, body):
    """Send email to LLM for parsing"""
    prompt = f"""
You are a strict email parser for placement mails.
Given the email subject and body, decide if this is a placement announcement.
- If yes, extract the following fields.
- If no, return is_relevant: "no" and set all fields to null.

Fields:
- is_relevant ("yes" or "no")
- company
- date_of_visit
- eligibility
- ctc
- stipend
- registration_deadline
- job_designation
- register_link

Return only valid JSON.

Email Subject:
{subject}

Email Body:
{body}

"""
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)

    def parse_llm_json(text):
        text = re.sub(r'^```json\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'^```', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\s*```$', '', text, flags=re.IGNORECASE)
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            print("⚠️ Failed to parse JSON:", e)
            print("Raw LLM output:\n", text)
            return None

    return parse_llm_json(response.text)


# === Main Function ===
def main():
    """Fetch latest CDC email, parse with LLM, push to Google Sheets"""
    creds = None
    if os.path.exists('token.json'):
        creds = UserCredentials.from_authorized_user_file('token.json', GMAIL_SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', GMAIL_SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)

    last_id = get_last_processed_id()

    # 🔎 Search for latest CDC email
    results = service.users().messages().list(
        userId='me',
        q='from:vitianscdc2026@vitstudent.ac.in -subject:"congratulations" -subject:"next round"',
        maxResults=50
    ).execute()

    messages = results.get('messages', [])
    if not messages:
        print("No CDC emails found.")
        return  
    
    new_messages = []
    for msg_meta in messages:
        if msg_meta["id"] == last_id:
            break  # stop once we reach last processed
        new_messages.append(msg_meta)

    if not new_messages:
        print("No new mails since last scan.")
        return

    for msg_meta in reversed(new_messages):
        msg = service.users().messages().get(
            userId='me', id=msg_meta['id']
        ).execute()

        payload = msg['payload']
        subject = next((h['value'] for h in payload['headers'] if h['name'] == 'Subject'), None)
        body = extract_clean_body(payload)
        body = postprocess_email_text(body)
        email_link = f"https://mail.google.com/mail/u/0/#inbox/{msg_meta['id']}"

        data = extract_email_data(subject, body)
        append_to_sheet(sheet, data, email_link)

        print("\n=== Subject ===\n", subject)
        print("\n=== Link ===\n", email_link)
        print("\n=== Clean Body ===\n", body if body else "No readable body found.")
        print("\n=== LLM JSON Output ===\n", json.dumps(data, indent=2))
    
    save_last_processed_id(messages[0]["id"])


if __name__ == '__main__':
    main()
