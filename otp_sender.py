import os
import sys
import time
import logging
import threading
import requests
import traceback
import base64
from urllib.parse import urlparse, parse_qs
from pyzbar.pyzbar import decode
from PIL import Image
import pyotp

# Configure logging with explicit file handling
log_file = 'otp_sender.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(log_file, mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Ensure logs are written immediately
logging.getLogger().handlers[0].flush = sys.stdout.flush

# Global configuration
CONFIG = {
    'MAX_RETRIES': 3,
    'TIMEOUT': 10,
    'RETRY_DELAY': 3,
    'FALLBACK_METHOD': 'print'
}

# Global flag to control the OTP generation loop
running = False

# Get the absolute path of the QR code file
QR_CODE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qrcode.jpg')

def log_and_print(message, level='info'):
    """Log message and print to console"""
    print(message)
    if level == 'info':
        logging.info(message)
    elif level == 'error':
        logging.error(message)
    elif level == 'warning':
        logging.warning(message)
    
    # Explicitly flush the log file
    logging.getLogger().handlers[0].flush()

def fallback_send_otp(message):
    """Send OTP using alternative methods"""
    try:
        log_and_print(f"FALLBACK MESSAGE: {message}")
        
        # Write to file
        with open('otp_fallback.txt', 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    except Exception as e:
        log_and_print(f"Fallback sending failed: {e}", 'error')

def send_telegram_message(bot_token, chat_id, message):
    """Send Telegram message with error handling"""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    # First, verify bot token and get bot information
    try:
        get_me_url = f"https://api.telegram.org/bot{bot_token}/getMe"
        bot_info = requests.get(get_me_url, timeout=CONFIG['TIMEOUT'])
        if bot_info.status_code != 200:
            log_and_print(f"Invalid bot token or bot not accessible. Status: {bot_info.status_code}", 'error')
            return False
        log_and_print(f"Bot verification successful: {bot_info.json()['result']['username']}")
    except Exception as e:
        log_and_print(f"Bot verification failed: {e}", 'error')
        return False

    # Ensure chat_id is in the correct format
    chat_id_str = str(chat_id)
    if chat_id_str.startswith('-100'):
        pass  # Already in correct format for supergroup
    elif chat_id_str.startswith('-'):
        chat_id_str = f"-100{chat_id_str[1:]}"  # Convert to supergroup format
    
    for attempt in range(CONFIG['MAX_RETRIES']):
        try:
            log_and_print(f"Telegram Message Sending - Attempt {attempt + 1}")
            
            response = requests.post(
                url, 
                json={
                    'chat_id': chat_id_str,
                    'text': message,
                    'parse_mode': 'HTML'
                },
                timeout=CONFIG['TIMEOUT']
            )
            
            log_and_print(f"Response Status: {response.status_code}")
            response_json = response.json()
            
            if response.status_code == 200 and response_json.get('ok', False):
                log_and_print("Message sent successfully")
                return True
            else:
                error_description = response_json.get('description', 'Unknown error')
                log_and_print(f"Telegram API Error: {error_description}", 'error')
        
        except requests.exceptions.RequestException as req_err:
            log_and_print(f"Network Request Error: {req_err}", 'error')
        
        except Exception as e:
            log_and_print(f"Unexpected Error: {str(e)}", 'error')
        
        # Wait before retry
        time.sleep(CONFIG['RETRY_DELAY'])
    
    # Fallback if all attempts fail
    fallback_send_otp(message)
    return False

def read_qr_code(file_path):
    """Read secret from QR code"""
    try:
        log_and_print(f"Reading QR code from: {file_path}")
        
        image = Image.open(file_path)
        decoded_objects = decode(image)
        
        if not decoded_objects:
            log_and_print("No QR codes found in the image", 'error')
            return None
        
        for obj in decoded_objects:
            uri = obj.data.decode('utf-8')
            log_and_print(f"Full QR Code URI: {uri}")
            
            parsed_uri = urlparse(uri)
            query_params = parse_qs(parsed_uri.query)
            
            if 'secret' in query_params:
                secret = query_params['secret'][0]
                log_and_print(f"Extracted Secret: {secret}")
                return secret
        
        log_and_print("No secret found in QR code", 'error')
        return None
    
    except Exception as e:
        log_and_print(f"QR Code Reading Error: {e}", 'error')
        return None

def otp_generation_thread(secret, bot_token, chat_id):
    """Generate and send OTPs"""
    global running
    totp = pyotp.TOTP(secret)
    
    while running:
        try:
            otp = totp.now()
            log_and_print(f"Generated OTP: {otp}")
            
            # Send OTP via Telegram
            send_telegram_message(bot_token, chat_id, f"Your OTP is: {otp}")
            
            time.sleep(30)  # Wait between OTP generations
        
        except Exception as e:
            log_and_print(f"OTP Generation/Sending Error: {e}", 'error')
            running = False

def main():
    global running
    
    log_and_print("Starting OTP Sender")
    
    # Updated bot token and chat ID format
    bot_token = '7426554501:AAG0b0XsIqKIL1sXFevZjOw4qdYzIKeE-3o'
    chat_id = '-4728543187'  # Will be formatted in send_telegram_message
    
    # Verify Telegram bot setup first
    test_message = "🤖 OTP Sender Bot is starting up..."
    if not send_telegram_message(bot_token, chat_id, test_message):
        log_and_print("Failed to verify Telegram bot setup. Please check your bot token and chat ID.", 'error')
        return
    
    # Read QR code
    secret = read_qr_code(QR_CODE_FILE)
    if not secret:
        log_and_print("QR Code reading failed", 'error')
        return
    
    # Validate secret
    try:
        base64.b32decode(secret.upper())
    except Exception as e:
        log_and_print(f"Invalid secret: {e}", 'error')
        return
    
    # Start OTP generation
    running = True
    otp_thread = threading.Thread(target=otp_generation_thread, args=(secret, bot_token, chat_id))
    otp_thread.start()
    
    # Interactive stop
    try:
        input("Press Enter to stop OTP generation...\n")
        running = False
        otp_thread.join()
    except KeyboardInterrupt:
        running = False
        otp_thread.join()
    
    log_and_print("OTP Sender Stopped")

if __name__ == "__main__":
    main()
