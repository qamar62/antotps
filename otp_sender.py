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
CHAT_ID = '-1001854583762'  # Converted to supergroup format (prefix with -100)
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
    
    # Try multiple chat ID formats
    chat_ids_to_try = [
        CHAT_ID,              # Original format
        f"-100{CHAT_ID[1:]}", # Supergroup format with -100 prefix
        f"-{CHAT_ID[1:]}",    # Without the first dash
        f"-1001854583762",    # Calculated ID
        f"-4747582386"        # Original ID from URL
    ]
    
    for chat_id in chat_ids_to_try:
        try:
            log_message(f"Trying to send with chat_id: {chat_id}")
            response = requests.post(
                url, 
                json={
                    'chat_id': chat_id,
                    'text': message,
                    'parse_mode': 'HTML'
                },
                timeout=TIMEOUT
            )
            
            log_message(f"Response: {response.status_code} - {response.text}")
            
            if response.status_code == 200 and response.json().get('ok', False):
                log_message(f"Message sent successfully with chat_id: {chat_id}")
                return True
        except Exception as e:
            log_message(f"Error with chat_id {chat_id}: {e}", 'error')
    
    log_message("Failed to send message with all chat ID formats", 'error')
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

def verify_bot_permissions():
    """Verify that the bot has the necessary permissions"""
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/getMe"
        response = requests.get(url, timeout=TIMEOUT)
        log_message(f"Bot check response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                log_message(f"Bot verification successful - @{bot_info['result']['username']}")
                return True
        
        log_message("Bot verification failed", 'error')
        return False
    except Exception as e:
        log_message(f"Bot verification error: {e}", 'error')
        return False

def get_chat_info():
    """Get information about the chat to verify access"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getChat"
    
    chat_ids_to_try = [
        CHAT_ID,
        f"-100{CHAT_ID[1:]}",
        f"-{CHAT_ID[1:]}",
        f"-1001854583762",
        f"-4747582386"
    ]
    
    for chat_id in chat_ids_to_try:
        try:
            log_message(f"Getting info for chat_id: {chat_id}")
            response = requests.post(
                url,
                json={'chat_id': chat_id},
                timeout=TIMEOUT
            )
            
            log_message(f"Response: {response.status_code} - {response.text}")
            
            if response.status_code == 200:
                chat_info = response.json()
                if chat_info.get('ok'):
                    log_message(f"Found valid chat: {chat_info['result'].get('title', 'Unknown')}")
                    log_message(f"Chat type: {chat_info['result'].get('type', 'Unknown')}")
                    return chat_id
        except Exception as e:
            log_message(f"Error getting chat info for {chat_id}: {e}", 'error')
    
    return None

def main():
    global running
    
    log_message("Starting OTP Sender Bot")
    
    # Verify bot token
    if not verify_bot_permissions():
        log_message("Bot verification failed. Please check your token.", 'error')
        return
    
    # Get valid chat ID
    valid_chat_id = get_chat_info()
    if valid_chat_id:
        log_message(f"Using chat ID: {valid_chat_id}")
    else:
        log_message("Failed to find a valid chat. Please check the chat ID.", 'error')
        log_message("Continuing anyway with the configured ID...", 'warning')
    
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
    
    # Generate a test OTP immediately
    handle_command('/otp', pyotp.TOTP(secret))
    
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
