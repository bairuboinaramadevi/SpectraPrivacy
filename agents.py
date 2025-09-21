"""
agents.py
LLM agents wrapping db_tools for authentication + querying.
Adds restartability by saving state to progress.json after each DB task.
"""

import logging
import os
import json
from typing import Optional
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool, ToolContext
from google.adk.agents.callback_context import CallbackContext
from google.adk.models import LlmResponse, LlmRequest


import db_tools

# --- PDF PII Processing Functions and Helpers (from notebook) ---
import io
import base64
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from presidio_analyzer import AnalyzerEngine
from typing import Dict, List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Use small spaCy model for Presidio Analyzer to avoid memory errors
from presidio_analyzer.nlp_engine import NlpEngineProvider

_spacy_config = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "en", "model_name": "en_core_web_sm"}
    ]
}
_provider = NlpEngineProvider(nlp_configuration=_spacy_config)
_nlp_engine = _provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=_nlp_engine, supported_languages=["en"])

def analyze_pdf_for_pii(pdf_path: str) -> Tuple[Dict[int, str], Dict[int, List]]:
    try:
        pdf_path = os.path.abspath(pdf_path)
        if not os.path.exists(pdf_path):
            print(f"Error: File not found at {pdf_path}")
            return {}, {}
        page_texts = {}
        page_results = {}
        with open(pdf_path, 'rb') as f:
            reader = PdfReader(f)
            for page_num, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                page_texts[page_num] = text
                results = analyzer.analyze(text=text, entities=[], language='en')
                # Convert RecognizerResult objects to dicts for serialization
                page_results[page_num] = [r.to_dict() for r in results]
        return page_texts, page_results
    except Exception as e:
        print(f"Error processing {pdf_path}: {e}")
        return {}, {}

def create_pdf_with_text(input_pdf_path: str, page_text_generator, output_path: str) -> bool:
    try:
        with open(input_pdf_path, 'rb') as f:
            pdf_reader = PdfReader(f)
            pdf_writer = PdfWriter()
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                page_width = float(page.mediabox.width)
                page_height = float(page.mediabox.height)
                packet = io.BytesIO()
                can = canvas.Canvas(packet, pagesize=(page_width, page_height))
                font_name = "Helvetica"
                font_size = 10
                can.setFont(font_name, font_size)
                can.setFillColorRGB(1, 1, 1)
                can.rect(0, 0, page_width, page_height, fill=True)
                can.setFillColorRGB(0, 0, 0)
                text_content = page_text_generator(page_num, page)
                if text_content:
                    text_object = can.beginText()
                    text_object.setTextOrigin(50, page_height - 50)
                    text_object.setFont(font_name, font_size)
                    for line in text_content.split('\n'):
                        if line.strip():
                            text_object.textLine(line)
                            text_object.moveCursor(0, font_size)
                    can.drawText(text_object)
                can.showPage()
                can.save()
                packet.seek(0)
                try:
                    new_pdf = PdfReader(packet)
                    watermark = new_pdf.pages[0]
                    page.merge_page(watermark)
                    pdf_writer.add_page(page)
                except Exception as e:
                    pdf_writer.add_blank_page(width=page_width, height=page_height)
            with open(output_path, 'wb') as output:
                pdf_writer.write(output)
            return os.path.exists(output_path)
    except Exception as e:
        print(f"Error creating PDF: {str(e)}")
        return False

def redact_pdf_pii(pdf_path: str, output_folder: str, page_texts: Dict[int, str], page_results: Dict[int, List]) -> None:
    try:
        pdf_path = os.path.abspath(pdf_path)
        output_folder = os.path.abspath(output_folder)
        if not os.path.exists(pdf_path):
            print(f"Error: Input file not found at {pdf_path}")
            return
        os.makedirs(output_folder, exist_ok=True)
        def generate_redacted_text(page_num, page):
            text = page_texts.get(page_num, "")
            results = page_results.get(page_num, [])
            if text and results:
                results.sort(key=lambda r: r["start"], reverse=True)
                redacted_text = text
                for result in results:
                    redacted_text = (
                        redacted_text[:result["start"]] +
                        "█" * (result["end"] - result["start"]) +
                        redacted_text[result["end"]:]
                    )
                return redacted_text
            return ""
        output_path = os.path.join(output_folder, os.path.basename(pdf_path))
        create_pdf_with_text(pdf_path, generate_redacted_text, output_path)
    except Exception as e:
        print(f"Error during redaction: {str(e)}")

def mask_pdf_pii(input_file, output_folder, page_texts, page_results):
    try:
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, os.path.basename(input_file))
        def get_smart_mask(text: str, entity_type: str) -> str:
            if len(text) <= 2:
                return "X" * len(text)
            if entity_type == "PHONE_NUMBER":
                return text[:2] + "X" * (len(text)-4) + text[-2:]
            elif entity_type == "EMAIL_ADDRESS":
                if "@" in text:
                    local, domain = text.split("@")
                    masked_local = local[:2] + "X" * (len(local)-2)
                    return f"{masked_local}@{domain}"
                return text[:2] + "X" * (len(text)-2)
            elif entity_type in ["PERSON", "FIRST_NAME", "LAST_NAME"]:
                return text[0] + "X" * (len(text)-2) + text[-1]
            else:
                return text[0] + "X" * (len(text)-2) + text[-1]
        def generate_masked_text(page_num, page):
            text = page_texts[page_num]
            results = page_results[page_num]
            if text and results:
                results.sort(key=lambda x: x["start"], reverse=True)
                masked_text = text
                for result in results:
                    original_text = text[result["start"]:result["end"]]
                    smart_mask = get_smart_mask(original_text, result["entity_type"])
                    masked_text = masked_text[:result["start"]] + smart_mask + masked_text[result["end"]:]
                return masked_text
            return ""
        create_pdf_with_text(input_file, generate_masked_text, output_file)
    except Exception as e:
        print(f"Error creating masked PDF: {str(e)}")

def anonymize_pdf_pii(input_file, output_folder, page_texts, page_results):
    try:
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, os.path.basename(input_file))
        def get_anonymous_replacement(text: str, entity_type: str) -> str:
            import random
            import string
            if entity_type == "PHONE_NUMBER":
                digits_only = ''.join(c for c in text if c.isdigit())
                random_digits = ''.join(random.choice(string.digits) for _ in range(len(digits_only)))
                result = text
                digit_index = 0
                for i, c in enumerate(text):
                    if c.isdigit():
                        result = result[:i] + random_digits[digit_index] + result[i+1:]
                        digit_index += 1
                return result
            elif entity_type == "EMAIL_ADDRESS":
                if "@" in text:
                    local, domain = text.split("@")
                    random_local = ''.join(random.choice(string.ascii_lowercase) for _ in range(len(local)))
                    return f"{random_local}@{domain}"
                return text
            elif entity_type in ["PERSON", "FIRST_NAME", "LAST_NAME"]:
                first_names = ["John", "Jane", "Michael", "Emily", "David", "Sarah", "James", "Emma",
                             "William", "Olivia", "Robert", "Sophia", "Joseph", "Isabella", "Thomas",
                             "Mia", "Charles", "Charlotte", "Daniel", "Amelia"]
                last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
                            "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
                            "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]
                words = text.split()
                if len(words) > 1:
                    parts = []
                    for i, word in enumerate(words):
                        if i == 0:
                            parts.append(random.choice(first_names))
                        elif i == len(words) - 1:
                            parts.append(random.choice(last_names))
                        else:
                            if len(word) == 1 or word.endswith('.'):
                                parts.append(random.choice(string.ascii_uppercase) + '.')
                            else:
                                parts.append(random.choice(first_names))
                    return ' '.join(parts)
                else:
                    return random.choice(first_names if entity_type == "FIRST_NAME" else last_names)
            elif entity_type == "ADDRESS":
                parts = text.split()
                for i, part in enumerate(parts):
                    if part.isdigit():
                        parts[i] = str(random.randint(1, 999))
                return " ".join(parts)
            elif entity_type == "DATE_TIME":
                import datetime
                try:
                    formats = ["%B %d, %Y", "%B %d", "%Y", "%y", "%m/%d/%Y", "%d/%m/%Y"]
                    parsed_date = None
                    for fmt in formats:
                        try:
                            parsed_date = datetime.datetime.strptime(text.strip(), fmt)
                            break
                        except ValueError:
                            continue
                    if parsed_date:
                        random_days = random.randint(-365*5, 365*5)
                        new_date = parsed_date + datetime.timedelta(days=random_days)
                        return new_date.strftime(fmt)
                    return text
                except:
                    return text
            elif entity_type == "NRP":
                nationalities = ["American", "Canadian", "British", "Australian", "French", "German", "Spanish", "Italian", "Japanese", "Korean", "Chinese", "Brazilian", "Mexican", "Indian", "Russian"]
                return random.choice(nationalities)
            elif entity_type == "US_SSN":
                parts = text.split('-')
                if len(parts) == 3:
                    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
                return ''.join(random.choice(string.digits) for _ in range(len(text)))
            else:
                result = ""
                for c in text:
                    if c.isalpha():
                        result += random.choice(string.ascii_letters)
                    elif c.isdigit():
                        result += random.choice(string.digits)
                    else:
                        result += c
                return result
        def generate_anonymized_text(page_num, page):
            text = page_texts[page_num]
            results = page_results[page_num]
            if text and results:
                results.sort(key=lambda x: x["start"], reverse=True)
                anonymized_text = text
                for result in results:
                    original_text = text[result["start"]:result["end"]]
                    anonymous_replacement = get_anonymous_replacement(original_text, result["entity_type"])
                    anonymized_text = (
                        anonymized_text[:result["start"]] + 
                        anonymous_replacement + 
                        anonymized_text[result["end"]:]
                    )
                return anonymized_text
            return ""
        create_pdf_with_text(input_file, generate_anonymized_text, output_file)
    except Exception as e:
        print(f"Error creating anonymized PDF: {str(e)}")

# --- Encryption/Decryption helpers ---
def generate_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

class PiiEncryption:
    def __init__(self, password: str, salt: bytes = None):
        self.key, self.salt = generate_key(password, salt)
        self.cipher = Fernet(self.key)
    def encrypt_text(self, text: str) -> str:
        encrypted = self.cipher.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    def decrypt_text(self, encrypted_text: str) -> str:
        try:
            decoded = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            print(f"Error decrypting text: {str(e)}")
            return "DECRYPTION_ERROR"

def encrypt_pdf_pii(input_file, output_folder, page_texts, page_results, password="your_secret_key"):
    try:
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, os.path.basename(input_file))
        encryptor = PiiEncryption(password)
        encryption_map = {"salt": base64.b64encode(encryptor.salt).decode(), "mappings": {}}
        def generate_encrypted_text(page_num, page):
            text = page_texts[page_num]
            results = page_results[page_num]
            if text and results:
                results.sort(key=lambda x: x["start"], reverse=True)
                encrypted_text = text
                for result in results:
                    original_text = text[result["start"]:result["end"]]
                    encrypted_value = encryptor.encrypt_text(original_text)
                    if page_num not in encryption_map["mappings"]:
                        encryption_map["mappings"][page_num] = []
                    encryption_map["mappings"][page_num].append({
                        "start": result["start"],
                        "end": result["end"],
                        "type": result["entity_type"],
                        "encrypted": encrypted_value
                    })
                    short_encrypted = f"[ENC:{len(encryption_map['mappings'][page_num])-1}]"
                    encrypted_text = encrypted_text[:result["start"]] + short_encrypted + encrypted_text[result["end"]:]
                return encrypted_text
            return ""
        create_pdf_with_text(input_file, generate_encrypted_text, output_file)
        mapping_file = os.path.join(output_folder, os.path.splitext(os.path.basename(input_file))[0] + "_encryption_map.json")
        with open(mapping_file, 'w') as f:
            json.dump(encryption_map, f, indent=2)
    except Exception as e:
        print(f"Error creating encrypted PDF: {str(e)}")

def decrypt_pdf_pii(encrypted_file, mapping_file, output_folder, password="your_secret_key"):
    try:
        with open(mapping_file, 'r') as f:
            encryption_map = json.load(f)
        salt = base64.b64decode(encryption_map["salt"])
        decryptor = PiiEncryption(password, salt)
        def generate_decrypted_text(page_num, page):
            text = page.extract_text()
            if str(page_num) in encryption_map["mappings"]:
                mappings = sorted(
                    encryption_map["mappings"][str(page_num)],
                    key=lambda x: x["start"],
                    reverse=True
                )
                decrypted_text = text
                for i, mapping in enumerate(mappings):
                    placeholder = f"[ENC:{i}]"
                    decrypted_value = decryptor.decrypt_text(mapping["encrypted"])
                    decrypted_text = decrypted_text.replace(placeholder, decrypted_value)
                return decrypted_text
            return text
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, "decrypted_" + os.path.basename(encrypted_file))
        create_pdf_with_text(encrypted_file, generate_decrypted_text, output_file)
    except Exception as e:
        print(f"Error decrypting PDF: {str(e)}")

def encrypt_pdf_with_pii(input_file, output_folder, user_password="user123", owner_password="owner456"):
    try:
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, os.path.basename(input_file))
        with open(input_file, 'rb') as file:
            reader = PdfReader(file)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.encrypt(
                user_password=user_password,
                owner_password=owner_password,
                use_128bit=True
            )
            with open(output_file, 'wb') as output:
                writer.write(output)
    except Exception as e:
        print(f"Error encrypting PDF: {str(e)}")

def highlight_pdf_pii(input_file, output_folder, page_texts, page_results):
    try:
        os.makedirs(output_folder, exist_ok=True)
        output_file = os.path.join(output_folder, os.path.basename(input_file))
        pdf_writer = PdfWriter()
        with open(input_file, 'rb') as file:
            pdf_reader = PdfReader(file)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                page_width = float(page.mediabox.width)
                page_height = float(page.mediabox.height)
                text = page_texts.get(page_num, "")
                results = page_results.get(page_num, [])
                if text and results:
                    packet = io.BytesIO()
                    can = canvas.Canvas(packet, pagesize=(page_width, page_height))
                    font_name = "Helvetica-Bold"
                    regular_font_size = 10
                    pii_font_size = 11
                    line_height = regular_font_size * 1.2
                    current_y = page_height - 50
                    current_position = 0
                    line_texts = []
                    for line in text.split('\n'):
                        if line.strip():
                            line_start = current_position
                            line_end = line_start + len(line)
                            line_highlights = []
                            line_segments = []
                            last_end = 0
                            line_results = [r for r in results if 
                                          (r.start >= line_start and r.start < line_end) or
                                          (r.end > line_start and r.end <= line_end) or
                                          (r.start <= line_start and r.end >= line_end)]
                            line_results.sort(key=lambda x: x.start)
                            for result in line_results:
                                highlight_start = max(0, result.start - line_start)
                                highlight_end = min(len(line), result.end - line_start)
                                if highlight_start > last_end:
                                    line_segments.append({
                                        'text': line[last_end:highlight_start],
                                        'is_pii': False
                                    })
                                line_segments.append({
                                    'text': line[highlight_start:highlight_end],
                                    'is_pii': True,
                                })
                                start_x = 50 + last_end * (regular_font_size * 0.6)
                                width = (highlight_end - highlight_start) * (pii_font_size * 0.7)
                                height = pii_font_size * 1.3
                                can.roundRect(start_x, current_y - 2, width, height, 2, fill=True)
                                last_end = highlight_end
                            if last_end < len(line):
                                line_segments.append({
                                    'text': line[last_end:],
                                    'is_pii': False
                                })
                            line_texts.append({
                                'y': current_y,
                                'segments': line_segments
                            })
                            current_y -= line_height
                            current_position = line_end + 1
                    for line in line_texts:
                        x_pos = 50
                        for segment in line['segments']:
                            if segment['is_pii']:
                                can.setFont(font_name, pii_font_size)
                                can.setFillColorRGB(0, 0, 0)
                            else:
                                can.setFont("Helvetica", regular_font_size)
                                can.setFillColorRGB(0, 0, 0)
                            can.drawString(x_pos, line['y'], segment['text'])
                            x_pos += can.stringWidth(segment['text'], 
                                                   font_name if segment['is_pii'] else "Helvetica",
                                                   pii_font_size if segment['is_pii'] else regular_font_size)
                    can.save()
                    packet.seek(0)
                    highlights_pdf = PdfReader(packet)
                    highlight_page = highlights_pdf.pages[0]
                    pdf_writer.add_page(highlight_page)
                else:
                    pdf_writer.add_page(page)
        with open(output_file, 'wb') as output:
            pdf_writer.write(output)
    except Exception as e:
        print(f"Error creating highlighted PDF: {str(e)}")

logger = logging.getLogger("agents")

PROGRESS_FILE = "progress.json"

import os
import PyPDF2
import json
import io
import base64
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from presidio_analyzer import AnalyzerEngine
from typing import Dict, List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



# Initialize the analyzer


    


def create_pdf_with_text(input_pdf_path: str, page_text_generator, output_path: str) -> bool:
    """
    Creates a PDF with text content using a generator function for text content.
    
    Args:
        input_pdf_path (str): Path to the input PDF to get dimensions from
        page_text_generator: Function that takes (page_num, page) and returns the text for that page
        output_path (str): Path where the output PDF should be saved
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Open the input PDF
        print(f"Opening input file: {input_pdf_path}")
        with open(input_pdf_path, 'rb') as f:
            pdf_reader = PdfReader(f)
            pdf_writer = PdfWriter()
            
            # Process each page
            for page_num in range(len(pdf_reader.pages)):
                # Get the original page
                page = pdf_reader.pages[page_num]
                page_width = float(page.mediabox.width)
                page_height = float(page.mediabox.height)
                
                # Create a new PDF page using reportlab
                packet = io.BytesIO()
                can = canvas.Canvas(packet, pagesize=(page_width, page_height))
                
                # Set up the font and size
                font_name = "Helvetica"
                font_size = 10
                can.setFont(font_name, font_size)
                
                # Start with a clean slate
                can.setFillColorRGB(1, 1, 1)  # White background
                can.rect(0, 0, page_width, page_height, fill=True)
                
                # Set up text drawing
                can.setFillColorRGB(0, 0, 0)  # Black text
                
                # Get the text content for this page from the generator
                text_content = page_text_generator(page_num, page)
                
                if text_content:
                    # Create text object for more control
                    text_object = can.beginText()
                    text_object.setTextOrigin(50, page_height - 50)  # Start 50 points from left and top
                    text_object.setFont(font_name, font_size)
                    
                    # Add each line with extra spacing
                    for line in text_content.split('\n'):
                        if line.strip():  # Only process non-empty lines
                            text_object.textLine(line)
                            text_object.moveCursor(0, font_size)  # Add extra line space
                    
                    can.drawText(text_object)
                
                # Save the current page
                can.showPage()
                can.save()
                
                # Move to the start of the packet
                packet.seek(0)
                
                try:
                    # Create a new PDF with the text
                    new_pdf = PdfReader(packet)
                    # Get the watermarked page
                    watermark = new_pdf.pages[0]
                    # Merge with original
                    page.merge_page(watermark)
                    # Add to writer
                    pdf_writer.add_page(page)
                except Exception as e:
                    print(f"Error processing page {page_num + 1}: {str(e)}")
                    # Add a blank page if there's an error
                    pdf_writer.add_blank_page(width=page_width, height=page_height)
            
            # Save the final PDF
            print(f"Saving PDF to: {output_path}")
            with open(output_path, 'wb') as output:
                pdf_writer.write(output)
            
            if os.path.exists(output_path):
                print(f"Successfully saved PDF. File size: {os.path.getsize(output_path)} bytes")
                return True
            else:
                print("Error: File was not saved successfully")
                return False
                
    except Exception as e:
        print(f"Error creating PDF: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
def redact_pdf_pii(pdf_path: str, output_folder: str, page_texts: Dict[int, str], page_results: Dict[int, List]) -> None:
    """
    Create redacted PDF using pre-analyzed PII results
    """
    try:
        # Convert paths to absolute paths
        pdf_path = os.path.abspath(pdf_path)
        output_folder = os.path.abspath(output_folder)
        
        if not os.path.exists(pdf_path):
            print(f"Error: Input file not found at {pdf_path}")
            return
            
        print(f"Processing file: {pdf_path}")
        print(f"Output folder: {output_folder}")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)
        
        def generate_redacted_text(page_num, page):
            """Generate redacted text for a page"""
            text = page_texts.get(page_num, "")
            results = page_results.get(page_num, [])
            
            if text and results:
                # Sort results by start index descending to avoid offset issues
                results.sort(key=lambda r: r["start"], reverse=True)
                
                # Replace each PII with black boxes
                redacted_text = text
                for result in results:
                    redacted_text = (
                        redacted_text[:result["start"]] +
                        "█" * (result["end"] - result["start"]) +
                        redacted_text[result["end"]:]
                    )
                return redacted_text
            return ""
        
        # Create the redacted PDF
        output_path = os.path.join(output_folder, os.path.basename(pdf_path))
        success = create_pdf_with_text(pdf_path, generate_redacted_text, output_path)
        
        if not success:
            print("Failed to create redacted PDF")
                
    except Exception as e:
        print(f"Error during redaction: {str(e)}")
        import traceback
        traceback.print_exc()



# ------------------------------------------------------------------
# Restartability helpers
# ------------------------------------------------------------------
def load_progress():
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"last_completed": -1}


def save_progress(idx):
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump({"last_completed": idx}, f)


# ------------------------------------------------------------------
# Logging callbacks
# ------------------------------------------------------------------
def before_model_log(callback_context: CallbackContext, llm_request: LlmRequest) -> None:
    try:
        text = getattr(llm_request, "instruction", "")
        logger.info(f"[{callback_context.agent_name}] Prompt: {text}")
    except Exception as e:
        logger.error(f"before_model_log error: {e}")


def after_model_log(callback_context: CallbackContext, llm_response: LlmResponse) -> None:
    try:
        text = (
            llm_response.content.parts[0].text
            if llm_response.content and llm_response.content.parts
            else ""
        )
        logger.info(f"[{callback_context.agent_name}] Response: {text}")
    except Exception as e:
        logger.error(f"after_model_log error: {e}")


# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------
def db_authenticate(db_name: str, tool_context: Optional[ToolContext] = None):
    configs = db_tools.load_config()
    secrets = db_tools.load_secrets()
    cfg = next(c for c in configs if c["db_name"] == db_name)

    password = secrets[db_name]["password"]
    success = db_tools.test_connection(cfg, password)
    return "SUCCESS" if success else "FAILURE"


def run_sample_query(db_name: str, idx: int, tool_context: Optional[ToolContext] = None):
    """
    Run query for db_name and update progress.json if successful.
    """
    configs = db_tools.load_config()
    secrets = db_tools.load_secrets()
    cfg = next(c for c in configs if c["db_name"] == db_name)
    password = secrets[db_name]["password"]

    rows = db_tools.execute_sample_query(cfg, password)

    # Save progress after success
    save_progress(idx)
    return f"Fetched {len(rows)} rows from {db_name}"


# ------------------------------------------------------------------
# Tools exposed to LLM
# ------------------------------------------------------------------
auth_tool = FunctionTool(db_authenticate)
query_tool = FunctionTool(run_sample_query)
redact_tool = FunctionTool(redact_pdf_pii)


# ------------------------------------------------------------------
# Agents
# ------------------------------------------------------------------




# --- PDF PII FunctionTools and Agents ---
from google.adk.tools import FunctionTool

analyze_pii_tool = FunctionTool(analyze_pdf_for_pii)
create_pdf_tool = FunctionTool(create_pdf_with_text)
redact_pdf_tool = FunctionTool(redact_pdf_pii)
mask_pdf_tool = FunctionTool(mask_pdf_pii)
anonymize_pdf_tool = FunctionTool(anonymize_pdf_pii)
encrypt_pdf_tool = FunctionTool(encrypt_pdf_pii)
decrypt_pdf_tool = FunctionTool(decrypt_pdf_pii)
encrypt_pdf_with_pii_tool = FunctionTool(encrypt_pdf_with_pii)
highlight_pdf_tool = FunctionTool(highlight_pdf_pii)

analyze_pii_agent = LlmAgent(
    name="AnalyzePIIAgent",
    model="gemini-2.5-flash",
    instruction="Detect PII in a PDF and return page texts and PII results.",
    tools=[analyze_pii_tool],
)

create_pdf_agent = LlmAgent(
    name="CreatePDFAgent",
    model="gemini-2.5-flash",
    instruction="Create a PDF with custom text content using a generator function.",
    tools=[create_pdf_tool],
)

redact_pdf_agent = LlmAgent(
    name="RedactPDFAgent",
    model="gemini-2.5-flash",
    instruction="Redact all detected PII in a PDF using pre-analyzed results.",
    tools=[redact_pdf_tool],
)

mask_pdf_agent = LlmAgent(
    name="MaskPDFAgent",
    model="gemini-2.5-flash",
    instruction="Mask PII in a PDF, keeping some identifying parts visible.",
    tools=[mask_pdf_tool],
)

anonymize_pdf_agent = LlmAgent(
    name="AnonymizePDFAgent",
    model="gemini-2.5-flash",
    instruction="Replace PII in a PDF with realistic but fake data.",
    tools=[anonymize_pdf_tool],
)

encrypt_pdf_agent = LlmAgent(
    name="EncryptPIIAgent",
    model="gemini-2.5-flash",
    instruction="Encrypt PII in a PDF, saving mapping for later decryption.",
    tools=[encrypt_pdf_tool],
)

decrypt_pdf_agent = LlmAgent(
    name="DecryptPIIAgent",
    model="gemini-2.5-flash",
    instruction="Decrypt a previously encrypted PDF using the mapping file.",
    tools=[decrypt_pdf_tool],
)

encrypt_pdf_with_pii_agent = LlmAgent(
    name="EncryptPDFWithPIIAgent",
    model="gemini-2.5-flash",
    instruction="Encrypt the entire PDF with password protection.",
    tools=[encrypt_pdf_with_pii_tool],
)

highlight_pdf_agent = LlmAgent(
    name="HighlightPIIAgent",
    model="gemini-2.5-flash",
    instruction="Highlight all detected PII in a PDF with a yellow background.",
    tools=[highlight_pdf_tool],
)


