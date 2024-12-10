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

def get_chat_id(bot_token):
    """Get chat ID from bot updates"""
    try:
        # First, delete any pending updates
        requests.get(f"https://api.telegram.org/bot{bot_token}/getUpdates?offset=-1")
        
        log_and_print("⚠️ Please follow these steps:")
        log_and_print("1. Open Telegram")
        log_and_print("2. Add the bot to your group")
        log_and_print("3. Make the bot an admin")
        log_and_print("4. Send a message saying '/start' in the group")
        log_and_print("Waiting for message... (30 seconds timeout)")
        
        # Wait for new message
        start_time = time.time()
        while time.time() - start_time < 30:
            response = requests.get(
                f"https://api.telegram.org/bot{bot_token}/getUpdates",
                timeout=CONFIG['TIMEOUT']
            )
            
            if response.status_code == 200:
                updates = response.json()
                if updates.get('ok') and updates.get('result'):
                    for update in updates['result']:
                        if 'message' in update:
                            chat_id = update['message']['chat']['id']
                            chat_type = update['message']['chat']['type']
                            chat_title = update['message']['chat'].get('title', 'Private Chat')
                            log_and_print(f"Found chat: {chat_title} (ID: {chat_id}, Type: {chat_type})")
                            return str(chat_id)
            
            time.sleep(1)
        
        log_and_print("No messages received within timeout", 'error')
        return None
    except Exception as e:
        log_and_print(f"Error getting chat ID: {e}", 'error')
        return None

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

def handle_command(command, chat_id, bot_token, totp):
    """Handle Telegram commands"""
    if command == '/otp':
        try:
            otp = totp.now()
            log_and_print(f"Generated OTP: {otp}")
            message = f"🔐 Your OTP is: <code>{otp}</code>\n⏱️ Valid for 30 seconds"
            send_telegram_message(bot_token, chat_id, message)
        except Exception as e:
            log_and_print(f"Error generating OTP: {e}", 'error')
    elif command == '/start':
        welcome_msg = """🤖 *OTP Bot Commands*
• /otp - Generate a new OTP
• /help - Show this help message"""
        send_telegram_message(bot_token, chat_id, welcome_msg)
    elif command == '/help':
        help_msg = """📖 *Available Commands*
• /otp - Generate a new OTP
• /help - Show this help message

ℹ️ The OTP will be valid for 30 seconds."""
        send_telegram_message(bot_token, chat_id, help_msg)

def listen_for_commands(secret, bot_token, chat_id):
    """Listen for Telegram commands"""
    global running
    totp = pyotp.TOTP(secret)
    last_update_id = 0
    
    log_and_print("Listening for commands. Send /help in Telegram for available commands.")
    
    while running:
        try:
            response = requests.get(
                f"https://api.telegram.org/bot{bot_token}/getUpdates",
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
                                handle_command(command, chat_id, bot_token, totp)
                        last_update_id = update['update_id']
            
            time.sleep(1)
            
        except Exception as e:
            log_and_print(f"Error in command listener: {e}", 'error')
            time.sleep(5)  # Wait before retrying

def main():
    global running
    
    log_and_print("Starting OTP Sender")
    
    # Bot configuration
    bot_token = '7426554501:AAG0b0XsIqKIL1sXFevZjOw4qdYzIKeE-3o'
    
    # Get chat ID automatically
    log_and_print("Getting chat ID...")
    chat_id = get_chat_id(bot_token)
    
    if not chat_id:
        log_and_print("Failed to get chat ID. Please make sure to:", 'error')
        log_and_print("1. Add the bot to your group", 'error')
        log_and_print("2. Make the bot an admin", 'error')
        log_and_print("3. Send a message in the group", 'error')
        return
    
    log_and_print(f"Using chat ID: {chat_id}")
    
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
    
    # Start command listener
    running = True
    command_thread = threading.Thread(
        target=listen_for_commands,
        args=(secret, bot_token, chat_id)
    )
    command_thread.start()
    
    # Send startup message
    startup_msg = """🤖 *OTP Bot is Online!*
Send /help to see available commands."""
    send_telegram_message(bot_token, chat_id, startup_msg)
    
    # Wait for stop signal
    try:
        input("Press Enter to stop the bot...\n")
        running = False
        command_thread.join()
    except KeyboardInterrupt:
        running = False
        command_thread.join()
    
    log_and_print("OTP Sender Stopped")

if __name__ == "__main__":
    main()
