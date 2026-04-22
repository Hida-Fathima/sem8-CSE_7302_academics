import re
import html
from werkzeug.utils import secure_filename
from config import ALLOWED_EXTENSIONS

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_input(text):
    """
    Sanitizes text to prevent XSS and Prompt Injection.
    """
    if not isinstance(text, str):
        text = str(text)
    
    # 1. HTML Escape (Prevent XSS in Dashboard)
    text = html.escape(text)
    
    # 2. Remove Control Characters (Prevent Log Injection)
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    # 3. Prompt Injection Defense (for Ollama)
    # We strip phrases that try to override the AI's system prompt
    injection_patterns = [
        r"(ignore previous instructions)",
        r"(system prompt)",
        r"(delete all)",
        r"(you are now)"
    ]
    for pattern in injection_patterns:
        text = re.sub(pattern, "[REDACTED_SECURITY]", text, flags=re.IGNORECASE)
        
    return text.strip()