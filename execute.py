import asyncio
import logging
import json
import os
from dotenv import load_dotenv
import uuid

import workflow
from agents import (
    analyze_pii_agent,
    redact_pdf_agent,
    mask_pdf_agent,
    anonymize_pdf_agent,
    encrypt_pdf_agent,
    decrypt_pdf_agent,
    encrypt_pdf_with_pii_agent,
    highlight_pdf_agent,
)
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


load_dotenv()

APP_NAME = "DBAutotuneApp"
USER_ID = "test_user"

PROGRESS_FILE = os.path.join("data", "progress.json")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("events.log", mode="w", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("event_logger")
logging.getLogger("google").setLevel(logging.WARNING)

def load_progress():
    """Load last completed DB index from progress.json."""
    if not os.path.exists(PROGRESS_FILE):
        return {"last_completed": -1}
    with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_progress(idx: int):
    """Save last completed DB index."""
    with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
        json.dump({"last_completed": idx}, f, indent=2)


async def run_agent(agent, instruction, session_service):
    """Helper to create session and run the agent with instruction."""
    session_id = str(uuid.uuid4())
    initial_state = {
        "user_name": USER_ID,
        "task": instruction,
    }
    await session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
        session_id=session_id,
        state=initial_state,
    )

    runner = Runner(agent=agent, app_name=APP_NAME, session_service=session_service)
    new_message = types.Content(role="user", parts=[types.Part(text=instruction)])

    response_text = None
    async for event in runner.run_async(user_id=USER_ID, session_id=session_id, new_message=new_message):
        if event.is_final_response():
            response_text = event.content.parts[0].text if event.content and event.content.parts else None

    return response_text


async def main():
    print("🚀 Starting workflow with restartability...")

    progress = load_progress()
    last_completed = progress.get("last_completed", -1)

    session_service = InMemorySessionService()


    # Process all PDFs in the input folder
    input_folder = "NasscomData/StructuredDataPDF/RawData/"
    redacted_folder = "NasscomData/StructuredDataPDF/RedactedData"
    masked_folder = "NasscomData/StructuredDataPDF/MaskedData"
    anonymized_folder = "NasscomData/StructuredDataPDF/AnonymizedData"
    encrypted_folder = "NasscomData/StructuredDataPDF/EncryptedData"
    decrypted_folder = "NasscomData/StructuredDataPDF/DecryptedData"
    highlighted_folder = "NasscomData/StructuredDataPDF/HighlightedData"

    pdf_files = [f for f in os.listdir(input_folder) if f.lower().endswith('.pdf')]
    print(f"Found {len(pdf_files)} PDF files in {input_folder}")


    from agents import analyze_pdf_for_pii, redact_pdf_pii, mask_pdf_pii, anonymize_pdf_pii

    for pdf_file in pdf_files:
        input_pdf = os.path.join(input_folder, pdf_file)
        print(f"\nProcessing: {input_pdf}")

        # Step 1: Analyze PII (direct function call)
        page_texts, page_results = analyze_pdf_for_pii(input_pdf)
        print(f"[PII Analysis] page_texts keys: {list(page_texts.keys())}, page_results keys: {list(page_results.keys())}")

        # Step 2: Redact PII (direct function call)
        print(f"[Redact] Redacting PII...")
        redact_pdf_pii(input_pdf, redacted_folder, page_texts, page_results)
        print(f"[Redact] Done. Redacted PDF saved to {redacted_folder}")

        # Step 3: Mask PII (direct function call)
        print(f"[Mask] Masking PII...")
        mask_pdf_pii(input_pdf, masked_folder, page_texts, page_results)
        print(f"[Mask] Done. Masked PDF saved to {masked_folder}")

        # Step 4: Anonymize PII (direct function call)
        print(f"[Anonymize] Anonymizing PII...")
        anonymize_pdf_pii(input_pdf, anonymized_folder, page_texts, page_results)
        print(f"[Anonymize] Done. Anonymized PDF saved to {anonymized_folder}")


    # Step 5: Encrypt PII (direct function call)
    print(f"[Encrypt] Encrypting PII...")
    from agents import encrypt_pdf_pii
    encrypt_pdf_pii(input_pdf, encrypted_folder, page_texts, page_results)
    print(f"[Encrypt] Done. Encrypted PDF saved to {encrypted_folder}")

    # Step 6: Highlight PII (direct function call)
    print(f"[Highlight] Highlighting PII...")
    from agents import highlight_pdf_pii
    highlight_pdf_pii(input_pdf, highlighted_folder, page_texts, page_results)
    print(f"[Highlight] Done. Highlighted PDF saved to {highlighted_folder}")

    print("✅ All PDF/PII agent tasks completed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"❌ Runtime crashed: {e}")
