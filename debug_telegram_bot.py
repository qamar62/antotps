import requests
import json
import sys

# Bot token from the original code
BOT_TOKEN = '7753763767:AAHSfbg1sHNsF2zfh-5j5yNoA464LaAHNuk'

def print_section(title):
    """Print a section title for better readability"""
    print("\n" + "=" * 50)
    print(title)
    print("=" * 50)

def verify_bot():
    """Verify that the bot token is valid"""
    print_section("BOT VERIFICATION")
    
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getMe"
    try:
        response = requests.get(url)
        print(f"Status code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200 and response.json().get('ok'):
            print("\n✅ Bot token is valid!")
            return True
        else:
            print("\n❌ Bot token is NOT valid!")
            return False
    except Exception as e:
        print(f"\n❌ Error checking bot: {e}")
        return False

def try_chat_ids():
    """Try different chat ID formats"""
    print_section("CHAT ID TESTING")
    
    # List of chat IDs to try in different formats
    chat_ids = [
        "-4747582386",           # Original ID
        "-1001854583762",        # Calculated ID
        "4747582386",            # Without minus
        "-100" + "4747582386",   # Another format
    ]
    
    for chat_id in chat_ids:
        print(f"\nTrying chat_id: {chat_id}")
        
        # First try getChat to see if the bot can access this chat
        try:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getChat"
            response = requests.post(url, json={'chat_id': chat_id})
            print(f"getChat status: {response.status_code}")
            print(f"getChat response: {json.dumps(response.json(), indent=2)}")
            
            # If getChat worked, try sending a message
            if response.status_code == 200:
                url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
                msg_response = requests.post(
                    url, 
                    json={
                        'chat_id': chat_id,
                        'text': f"🧪 Test message with chat_id: {chat_id}"
                    }
                )
                print(f"sendMessage status: {msg_response.status_code}")
                print(f"sendMessage response: {json.dumps(msg_response.json(), indent=2)}")
                
                if msg_response.status_code == 200:
                    print(f"\n✅ Success with chat_id: {chat_id}")
        except Exception as e:
            print(f"Error with chat_id {chat_id}: {e}")

def get_bot_updates():
    """Check recent updates to see if the bot is receiving messages"""
    print_section("RECENT UPDATES")
    
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
    try:
        response = requests.get(url)
        print(f"Status code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            updates = response.json()
            if updates.get('ok') and updates['result']:
                print("\n✅ Bot is receiving messages!")
                
                # Extract chat IDs from updates
                print("\nChat IDs found in updates:")
                for update in updates['result']:
                    if 'message' in update and 'chat' in update['message']:
                        chat = update['message']['chat']
                        print(f"- ID: {chat['id']}, Type: {chat['type']}, Title: {chat.get('title', 'Private')}")
            else:
                print("\n⚠️ No recent updates. Try sending a message to the bot.")
    except Exception as e:
        print(f"\n❌ Error checking updates: {e}")

def get_bot_chats():
    """Try to get a list of chats the bot is in"""
    print_section("BOT CHATS")
    
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getMyCommands"
    try:
        response = requests.get(url)
        print(f"getMyCommands Status: {response.status_code}")
        print(f"Commands: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        print(f"Error getting commands: {e}")

if __name__ == "__main__":
    print("\n🤖 TELEGRAM BOT DEBUGGER 🤖\n")
    
    if verify_bot():
        get_bot_updates()
        try_chat_ids()
        get_bot_chats()
    else:
        print("Fix bot token before continuing.")
        sys.exit(1)
