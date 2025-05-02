import time
import logging
import threading
import requests
import base64
from urllib.parse import urlparse, parse_qs
from pyzbar.pyzbar import decode
from PIL import Image
import pyotp

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('otp_sender.log', mode='w'),
        logging.StreamHandler()
    ]
)

# QR code file path (in the same directory as the script)
QR_CODE_FILE = 'qrcode.jpg'

# Hardcoded configuration
BOT_TOKEN = '7753763767:AAHSfbg1sHNsF2zfh-5j5yNoA464LaAHNuk'
CHAT_ID = '-4747582386'  # Hardcoded as requested
TIMEOUT = 10
RETRY_DELAY = 3

# Global flag to control the OTP generation loop
running = False

def log_message(message, level='info'):
    """Log message and print to console"""
    print(message)
    if level == 'info':
        logging.info(message)
    elif level == 'error':
        logging.error(message)
    elif level == 'warning':
        logging.warning(message)

def send_telegram_message(message):
    """Send Telegram message"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    
    try:
        response = requests.post(
            url, 
            json={
                'chat_id': CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            },
            timeout=TIMEOUT
        )
        
        if response.status_code == 200 and response.json().get('ok', False):
            log_message("Message sent successfully")
            return True
        else:
            error_description = response.json().get('description', 'Unknown error')
            log_message(f"Telegram error: {error_description}", 'error')
            return False
            
    except Exception as e:
        log_message(f"Error sending message: {e}", 'error')
        return False

def read_qr_code():
    """Read secret from QR code"""
    try:
        log_message(f"Reading QR code from: {QR_CODE_FILE}")
        
        image = Image.open(QR_CODE_FILE)
        decoded_objects = decode(image)
        
        if not decoded_objects:
            log_message("No QR codes found in the image", 'error')
            return None
        
        for obj in decoded_objects:
            uri = obj.data.decode('utf-8')
            
            parsed_uri = urlparse(uri)
            query_params = parse_qs(parsed_uri.query)
            
            if 'secret' in query_params:
                secret = query_params['secret'][0]
                log_message("Secret successfully extracted")
                return secret
        
        log_message("No secret found in QR code", 'error')
        return None
    
    except Exception as e:
        log_message(f"QR Code reading error: {e}", 'error')
        return None

def handle_command(command, totp):
    """Handle Telegram commands"""
    if command == '/otp':
        try:
            otp = totp.now()
            log_message(f"Generated OTP: {otp}")
            message = f"🔐 Your OTP is: <code>{otp}</code>\n⏱️ Valid for 30 seconds"
            send_telegram_message(message)
        except Exception as e:
            log_message(f"Error generating OTP: {e}", 'error')
    elif command == '/start':
        welcome_msg = """🤖 *OTP Bot Commands*
• /otp - Generate a new OTP
• /help - Show this help message"""
        send_telegram_message(welcome_msg)
    elif command == '/help':
        help_msg = """📖 *Available Commands*
• /otp - Generate a new OTP
• /help - Show this help message

ℹ️ The OTP will be valid for 30 seconds."""
        send_telegram_message(help_msg)

def listen_for_commands(secret):
    """Listen for Telegram commands"""
    global running
    totp = pyotp.TOTP(secret)
    last_update_id = 0
    
    log_message("Listening for commands. Send /help in Telegram for available commands.")
    
    while running:
        try:
            response = requests.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                params={
                    'offset': last_update_id + 1,
                    'timeout': 30
                }
            )
            
            if response.status_code == 200:
                updates = response.json()
                if updates.get('ok') and updates.get('result'):
                    for update in updates['result']:
                        if 'message' in update and 'text' in update['message']:
                            command = update['message']['text'].lower().strip()
                            if command.startswith('/'):
                                handle_command(command, totp)
                        last_update_id = update['update_id']
            
            time.sleep(1)
            
        except Exception as e:
            log_message(f"Error in command listener: {e}", 'error')
            time.sleep(5)  # Wait before retrying

def main():
    global running
    
    log_message("Starting OTP Sender Bot")
    
    # Read QR code
    secret = read_qr_code()
    if not secret:
        log_message("QR Code reading failed", 'error')
        return
    
    # Validate secret
    try:
        base64.b32decode(secret.upper())
    except Exception as e:
        log_message(f"Invalid secret: {e}", 'error')
        return
    
    # Start command listener
    running = True
    command_thread = threading.Thread(
        target=listen_for_commands,
        args=(secret,)
    )
    command_thread.daemon = True
    command_thread.start()
    
    # Send startup message
    startup_msg = "🤖 OTP Bot is Online! Send /help to see available commands."
    send_telegram_message(startup_msg)
    
    # Wait for stop signal
    try:
        print("Bot is running. Press Ctrl+C to stop...")
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        log_message("Stopping bot...")
        time.sleep(1)  # Give the command thread time to finish
    
    log_message("OTP Sender Bot Stopped")

if __name__ == "__main__":
    main()
