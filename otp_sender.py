import time
import logging
import threading
import requests
import base64
import json
from urllib.parse import urlparse, parse_qs
from pyzbar.pyzbar import decode
from PIL import Image
import pyotp

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('otp_sender.log', mode='w'),
        logging.StreamHandler()
    ]
)

# QR code file path
QR_CODE_FILE = 'qrcode.jpg'

# Bot configuration
BOT_TOKEN = '7753763767:AAHSfbg1sHNsF2zfh-5j5yNoA464LaAHNuk'
CHAT_ID = '-4747582386'  # We'll find the correct format dynamically

# Global flag to control the OTP generation loop
running = False
# Store the correct chat ID once found
correct_chat_id = None

def log_message(message, level='info'):
    """Log message and print to console"""
    print(message)
    if level == 'info':
        logging.info(message)
    elif level == 'error':
        logging.error(message)
    elif level == 'warning':
        logging.warning(message)

def find_correct_chat_id():
    """Find the correct chat ID format by testing multiple formats"""
    global correct_chat_id
    
    # Chat IDs to try
    chat_ids = [
        CHAT_ID,                 # Original format
        '-1001854583762',        # Calculated ID
        f"-100{CHAT_ID[1:]}",    # Adding the -100 prefix
        CHAT_ID[1:],             # Without the minus
    ]
    
    log_message("Finding the correct chat ID format...")
    
    # Try each chat ID format
    for chat_id in chat_ids:
        try:
            log_message(f"Testing chat ID: {chat_id}")
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getChat"
            response = requests.post(url, json={'chat_id': chat_id})
            
            if response.status_code == 200 and response.json().get('ok'):
                chat_info = response.json()['result']
                log_message(f"Found valid chat: {chat_info.get('title', 'Unknown')}")
                correct_chat_id = chat_id
                return chat_id
            else:
                error = response.json().get('description', 'Unknown error')
                log_message(f"Failed with chat ID {chat_id}: {error}")
        except Exception as e:
            log_message(f"Error testing chat ID {chat_id}: {e}", 'error')
    
    log_message("Could not find a valid chat ID format.", 'error')
    return None

def verify_bot():
    """Verify that the bot token is valid"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/getMe"
        response = requests.get(url)
        if response.status_code == 200 and response.json().get('ok'):
            bot_info = response.json()['result']
            log_message(f"Bot verified: @{bot_info['username']}")
            return True
        log_message("Invalid bot token", 'error')
        return False
    except Exception as e:
        log_message(f"Bot verification error: {e}", 'error')
        return False

def send_telegram_message(message):
    """Send Telegram message"""
    global correct_chat_id
    
    # If we haven't found the correct chat ID yet, try to find it
    if correct_chat_id is None:
        correct_chat_id = find_correct_chat_id()
        if correct_chat_id is None:
            log_message("Could not find a valid chat ID. Using default format.", 'error')
            correct_chat_id = CHAT_ID
    
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    
    try:
        response = requests.post(
            url, 
            json={
                'chat_id': correct_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            },
            timeout=10
        )
        
        # Log the full response for debugging
        log_message(f"API Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200 and response.json().get('ok'):
            log_message("Message sent successfully!")
            return True
        else:
            error = response.json().get('description', 'Unknown error')
            log_message(f"Message sending failed: {error}", 'error')
            # If chat not found, try to find the correct ID again next time
            if "chat not found" in error.lower():
                correct_chat_id = None
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

def listen_for_updates(secret):
    """Listen for Telegram updates"""
    global running
    totp = pyotp.TOTP(secret)
    last_update_id = 0
    
    log_message("Listening for commands...")
    
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
                if updates.get('ok') and updates['result']:
                    for update in updates['result']:
                        last_update_id = update['update_id']
                        
                        if 'message' in update and 'text' in update['message']:
                            command = update['message']['text'].lower().strip()
                            chat_id = update['message']['chat']['id']
                            
                            # Store this chat ID if we found one that works
                            global correct_chat_id
                            if correct_chat_id is None:
                                correct_chat_id = str(chat_id)
                                log_message(f"Found working chat ID from update: {correct_chat_id}")
                            
                            log_message(f"Received command: {command} from chat {chat_id}")
                            
                            if command == '/otp':
                                otp = totp.now()
                                log_message(f"Generated OTP: {otp}")
                                message = f"🔐 Your OTP is: <code>{otp}</code>\n⏱️ Valid for 30 seconds"
                                send_telegram_message(message)
                            elif command == '/start' or command == '/help':
                                help_msg = """📖 OTP Bot Commands:
• /otp - Generate a new OTP code
• /help - Show this help message

The OTP is valid for 30 seconds."""
                                send_telegram_message(help_msg)
            
            time.sleep(1)
        except Exception as e:
            log_message(f"Error in update listener: {e}", 'error')
            time.sleep(5)

def main():
    global running
    
    log_message("Starting OTP Sender Bot")
    
    # Verify bot token
    if not verify_bot():
        log_message("Bot verification failed. Check your token.", 'error')
        return
    
    # Try to find the correct chat ID format
    global correct_chat_id
    correct_chat_id = find_correct_chat_id()
    
    if correct_chat_id:
        log_message(f"Found correct chat ID format: {correct_chat_id}")
    else:
        log_message("Could not find correct chat ID format. Will try different formats.", 'warning')
    
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
    
    # Start update listener
    running = True
    listener_thread = threading.Thread(
        target=listen_for_updates,
        args=(secret,)
    )
    listener_thread.daemon = True
    listener_thread.start()
    
    # Send startup message
    startup_msg = "🤖 OTP Bot is Online! Send /otp to generate a one-time password."
    send_telegram_message(startup_msg)
    
    # Generate an initial OTP
    totp = pyotp.TOTP(secret)
    otp = totp.now()
    log_message(f"Initial OTP: {otp}")
    initial_otp_msg = f"🔐 Initial OTP: <code>{otp}</code>\n⏱️ Valid for 30 seconds"
    send_telegram_message(initial_otp_msg)
    
    # Main loop - keep generating OTPs periodically
    try:
        log_message("Bot is running. Press Ctrl+C to stop...")
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        log_message("Stopping bot...")
    
    log_message("OTP Sender Bot Stopped")

if __name__ == "__main__":
    main()
