from pynput.keyboard import Key, Listener
from datetime import datetime, timedelta
import time
import matplotlib.pyplot as plt
from collections import defaultdict
from wordcloud import WordCloud
import psutil
import os

# Constants
LOG_FILE = "educational_key_log1.txt"
ALERT_KEYWORDS = ["play", "game", "social", "video", "chat", "hello"]
REMINDER_INTERVAL = timedelta(minutes=30)  # Example: remind every 30 minutes
LESSON_TOPICS = ["math", "science", "history"]
NON_EDUCATIONAL_SITES = ["facebook.com", "instagram.com", "twitter.com", "tiktok.com", "snapchat.com", "youtube.com", "reddit.com", "pinterest.com", "tumblr.com", "linkedin.com", "whatsapp.com", "wechat.com", "telegram.org", "discord.com", "vimeo.com", "netflix.com", "hulu.com", "primevideo.com", "disneyplus.com", "hbo.com", "hotstar.com", "dailymotion.com", "soundcloud.com", "spotify.com", "apple.com", "google.com", "amazon.com", "ebay.com", "alibaba.com", "walmart.com", "bestbuy.com", "target.com", "homedepot.com", "costco.com", "macys.com", "kohls.com", "wayfair.com", "zillow.com", "craigslist.org", "yelp.com", "tripadvisor.com", "booking.com", "expedia.com", "airbnb.com", "trivago.com", "kayak.com", "orbitz.com", "cheapoair.com", "skyscanner.com", "hotels.com", "marriott.com", "hilton.com", "southwest.com", "united.com", "delta.com", "americanexpress.com", "paypal.com", "venmo.com"]

# Variables to store timestamps
start_time = None
end_time = None

# Variables
current_word = ""
key_usage = defaultdict(int)
student_behavior = {"focus_warnings": 0, "unrelated_content": 0}
alert_counts = defaultdict(int)

def send_reminder(message):
    print(f"Reminder: {message}")

def analyze_typing_patterns():
    return False

def check_vulnerable_words(word):
    vulnerable_words = ["password", "credit card", "ssn", "login","password", "hacker", "hacking", "crack", "cracked", "exploit", "phishing", "malware", "virus", "trojan", "worm", "spyware", "adware", "rootkit", "ransomware", "backdoor", "botnet", "keylogger", "brute force", "payload", "zero-day", "exploit", "social engineering", "DDoS", "denial of service", "cyberattack", "cybercrime", "cracker", "script kiddie", "phisher", "scammer", "black hat", "white hat", "gray hat", "hacker group", "security breach", "data breach", "identity theft", "data theft", "password cracking", "session hijacking", "SQL injection", "XSS", "cross-site scripting", "malicious code", "rogue software", "spybot", "keylogger", "sniffer", "packet sniffer", "mitm", "man-in-the-middle", "credential stuffing", "brute force attack", "social engineer", "payload delivery", "cyber espionage", "digital footprint", "vulnerability", "exploit kit", "web shell", "network intrusion", "phishing scam", "scam email", "fake website", "fake login", "fake profile", "identity scam", "spyware attack", "ad fraud", "click fraud", "data exfiltration", "credential harvesting", "drive-by download", "clickjacking", "scareware", "malicious link", "malicious email", "infected attachment", "virus infection", "worm outbreak", "trojan horse", "rootkit infection", "ransomware attack", "backdoor access", "botnet attack", "keylogging software", "password manager", "password dump", "data mining", "system compromise", "network breach", "data corruption", "source code theft", "phishing link", "fraudulent activity", "scam website", "black hat hacker", "white hat hacker", "gray hat hacker", "exploit development", "cyber threat", "cybersecurity", "data security", "security vulnerability", "network security", "system security", "malicious attack", "information theft", "spy software", "unauthorized access", "internet scam", "fraudulent email", "fake account", "false identity", "spoofing", "impersonation", "email spoofing", "website spoofing", "browser hijacking", "root access", "admin access", "unauthorized access", "web exploit", "network exploit", "code injection", "data breach", "security flaw", "confidential information", "sensitive data", "private information", "data compromise", "information leak", "password theft", "system exploit", "software exploit", "network hack", "cyber invasion", "data theft", "digital theft", "identity breach", "identity theft", "password theft", "cyber hacking", "internet fraud", "online scam", "digital scam", "fraudulent transaction", "unauthorized transaction", "internet hack", "digital hack", "network intrusion", "account hack", "website hack", "email hack", "system hack", "software hack", "computer virus", "network virus", "system virus", "malware attack", "adware attack", "spyware attack", "ransomware threat", "botnet threat", "cyber fraud", "web attack", "security exploit", "phishing attempt", "fraud attempt", "online fraud", "cyber scam", "cyber threat", "web scam", "social media hack", "account breach", "email breach", "login breach", "password breach", "confidential breach", "network threat", "digital breach", "internet threat", "software threat", "computer threat", "information threat", "security threat"
"123456", "123456789", "12345678", "12345", "1234567", "admin", "letmein", "welcome", "password1", "abc123", "qwerty", "123123", "password123", "123321", "qwerty123", "1q2w3e4r", "password1234", "password1", "123qwe", "password!", "letmein1", "1234", "password!", "iloveyou", "sunshine", "princess", "admin123", "welcome1", "qwertyuiop", "abc12345", "password12", "1q2w3e", "qwerty1", "admin1", "letmein123", "welcome123", "password12345", "password123456", "qwerty1", "password1", "password789", "iloveyou1", "12312345", "qwerty1234", "1q2w3e4r5t", "password!1", "password!12", "1q2w3e4r", "qwerty12", "123456a", "123456b", "password!123", "1234qwer", "1q2w3e4r5t6y", "password1234567", "1234567890", "letmein1234", "qwerty12345", "passwordq", "welcome12", "password12345678", "1q2w3e4r5t6y7u", "password1!", "letmein1!", "qwerty!1", "123qwe1", "1234password", "password2", "letmein12345", "qwerty12", "password321", "admin@123", "letmein@123", "admin1234", "welcome@123", "1234abcd", "password@123", "letmein@1234", "qwerty123", "123abcd", "letmein567", "admin@1234", "qwerty456", "12345abc", "password@1234", "letmein789", "123qwerty", "password!23", "letmein!23", "admin123456", "password12!", "letmein12!", "123456abc", "1234qwerty", "qwerty789", "letmein@1", "admin@12345", "password!1234", "12345qwerty", "1234abcd!", "admin!123", "qwerty!123", "1234567a", "password123!", "adminpassword", "letmeinpassword", "welcome1234", "1234abcde", "123abc456", "qwerty!12", "password!567", "letmein!567", "admin!1234", "1234password!", "123qwerty1", "letmein!1", "qwerty!1234", "password!12345", "letmeinpassword!", "admin!password", "qwerty!1", "12345password", "123qwerty2", "password!1", "letmein12345", "qwerty!12345", "admin12345", "welcome!123", "password!1", "1234567abc", "admin!12", "letmein!12", "qwerty123456", "12345abcde", "password!1234", "admin!password", "letmein!password", "welcome12345", "password1234", "qwerty!password", "1234567abcde", "letmein123", "admin@password", "123456a!", "1234qwerty1", "password@1", "letmein!12", "qwerty!123456", "adminpassword1", "123456a!2", "letmein123", "admin1234567", "welcome!password", "1234password123", "password!admin", "qwerty!admin", "123qwerty123", "admin123!password", "letmein!password123", "welcome12345!", "12345678abc", "123456789a", "adminpassword123", "password!12345", "letmeinpassword1", "admin!123456", "qwerty123!", "password@admin", "1234password!", "letmein12345", "admin123456789", "welcome!password1", "12345678a", "password12345", "admin!password1", "letmein!12345", "qwerty!1234567", "admin!password123", "1234qwerty", "password!admin123", "letmeinpassword!", "admin12345!", "123456a@123", "1234qwerty123", "letmeinpassword123", "adminpassword!1", "welcome!1234", "12345678", "1234567890", "admin12345678"]
    if any(vul_word in word.lower() for vul_word in vulnerable_words):
        alert_counts["vulnerable_words"] += 1
        return True
    return False

def avoid_personal_communication(word):
    personal_communication_keywords = ["hi", "hello", "hey","sup", "what's up", "yo", "bro", "sis", "dude", "buddy", "pal", "mate", "fam", "bruh", "howdy", "hola", "hey there", "yo yo", "wassup", "greetings", "salut", "how are you", "how u doin", "how r u", "hru", "good morning", "good night", "good evening", "good afternoon", "gm", "gn", "night", "nite", "morning", "afternoon", "evening", "babe", "baby", "honey", "sweetie", "darling", "dear", "love", "luv", "cutie", "handsome", "beautiful", "gorgeous", "pretty", "cute", "angel", "sugar", "sunshine", "boo", "bae", "wifey", "hubby", "kiss", "hugs", "xoxo", "mwah", "cya", "bye", "see ya", "ttyl", "talk to you later", "bbl", "be back later", "gtg", "got to go", "talk soon", "later", "laters", "peace", "take care", "take it easy", "miss you", "miss ya", "thinking of you", "can't wait", "can't wait to see you", "love you", "love u", "i love you", "ily", "i miss you", "imissyou", "forever", "always", "together", "us", "we", "forever yours", "yours", "forever and always", "4ever", "bae4ever", "you and me", "me and you", "soulmate", "my person", "bff", "bffs", "bestie", "besties", "bffl", "bffae", "friends", "forever friends", "best friend", "best friend forever", "friendship", "bond", "relationship", "bf", "gf", "boyfriend", "girlfriend", "crush", "admire", "adore", "sweetheart", "partner", "companion", "significant other", "other half", "better half", "my love", "my life", "my everything", "my world", "my heart", "my soul", "my one and only", "my moon", "my stars", "my sunshine", "my king", "my queen", "prince", "princess", "darlin", "sweetheart", "honeybun", "cuddle", "snuggle", "clingy", "cling", "affection", "romance", "romantic", "valentine", "true love", "heartthrob", "heartbeat", "crushin", "smitten", "flirty", "flirting", "date", "dating", "together forever", "forever love", "endless love", "eternal love", "in love", "head over heels", "crazy about you", "i'm yours", "you're mine", "promise", "pinkie promise", "together always", "together forever", "forever yours", "be mine", "you complete me", "you mean everything", "you are my world", "you're my person", "you're the one", "you're my everything"]
    if any(keyword in word.lower() for keyword in personal_communication_keywords):
        alert_counts["personal_communication"] += 1
        return True
    return False

def block_non_educational_sites(word):
    for site in NON_EDUCATIONAL_SITES:
        if site in word.lower():
            print(f"Access to {site} is blocked.")
            alert_counts["non_educational_sites"] += 1
            return True
    return False

def alert_teacher(message):
    print(f"Alert: {message}")
    student_behavior["focus_warnings"] += 1

def check_lesson_relevance(word):
    if not any(topic in word.lower() for topic in LESSON_TOPICS):
        student_behavior["unrelated_content"] += 1
        alert_counts["unrelated_content"] += 1
        alert_teacher(f"Unrelated content typed: {word}")

def focus_reminder():
    if student_behavior["focus_warnings"] > 3:
        print("Reminder: Please stay focused on the lesson.")

def generate_behavioral_heatmap():
    keys = list(key_usage.keys())
    values = list(key_usage.values())
    plt.bar(keys, values)
    plt.xlabel('Keys')
    plt.ylabel('Frequency')
    plt.title('Behavioral Heatmap')
    plt.show()

def real_time_threat_detection(word):
    if "threat" in word.lower():
        alert_counts["threat_detection"] += 1
        print("Potential threat detected!")

def data_loss_prevention(word):
    if "confidential" in word.lower() or "password" in word.lower():
        alert_counts["data_loss_prevention"] += 1
        print("Data loss prevention triggered.")

def behavior_based_access_control():
    pass

def get_consent():
    print("Ethical and legal considerations should include user consent, data privacy, and compliance with regulations.")
    consent = input("Do you consent to the use of a keylogger for educational purposes? (yes/no): ")
    return consent.lower() == "yes"

def start_keylogger():
    if get_consent():
        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()
    else:
        print("Consent not given. Keylogger will not start.")
        return

def track_typing_speed():
    start_time = time.time()
    total_keys = 0
    while True:
        elapsed_time = time.time() - start_time
        if elapsed_time > 60:  # Track for 60 seconds
            typing_speed = total_keys / elapsed_time
            print(f"Typing speed: {typing_speed} keys per second")
            break
        time.sleep(1)
        total_keys += 1

def monitor_key_usage():
    for key in key_usage:
        print(f"Key '{key}' pressed {key_usage[key]} times.")

def capture_special_keys():
    special_keys = ["space", "enter", "backspace", "shift", "ctrl", "alt", "tab", "esc"]
    for key in special_keys:
        if key in key_usage:
            print(f"Special key '{key}' pressed {key_usage[key]} times.")

def record_timestamps():
    with open(LOG_FILE, 'a') as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"{timestamp}: Logging started\n")

def log_typing_patterns():
    global current_word
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a') as file:
        for char in current_word:
            file.write(f"Typing pattern logged: {timestamp} - {char}\n")
    print(f"Typing pattern logged: {current_word}")

def count_words():
    global current_word
    words = current_word.split()
    word_count = len(words)
    print(f"Word count: {word_count}")

def track_error_keys():
    error_keys = ["caps_lock", "num_lock", "scroll_lock"]
    for key in error_keys:
        if key in key_usage:
            print(f"Error key '{key}' pressed {key_usage[key]} times.")

def analyze_long_keys():
    for key in key_usage:
        if len(key) > 5:
            print(f"Long key '{key}' pressed {key_usage[key]} times.")

def monitor_application_usage():
    for proc in psutil.process_iter(['pid', 'name']):
        print(f"Process ID: {proc.info['pid']}, Process Name: {proc.info['name']}")

def generate_summary_report():
    report = f"Summary Report:\nTotal key presses: {sum(key_usage.values())}\n"
    report += f"Focus warnings: {student_behavior['focus_warnings']}\n"
    report += f"Unrelated content incidents: {student_behavior['unrelated_content']}\n"
    report += f"Current time: {datetime.now()}\n"
    print(report)

def generate_pie_chart():
    labels = list(alert_counts.keys())
    sizes = list(alert_counts.values())

    if sum(sizes) > 0:
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title("Distribution of Alerts and Reminders")
        plt.axis('equal')
        plt.show()
    else:
        print("No alerts or reminders to display in pie chart.")

def generate_word_cloud():
    with open(LOG_FILE, 'r') as file:
        logged_data = file.read()

    words = logged_data.split()
    text = ' '.join(words)
    wordcloud = WordCloud(width=800, height=400, background_color='white').generate(text)

    plt.figure(figsize=(10, 5))
    plt.imshow(wordcloud, interpolation='bilinear')
    plt.axis('off')
    plt.title('Word Cloud of Captured Words')
    plt.show()

def on_press(key):
    global current_word
    global key_usage
    global start_time
    if start_time is None:
        start_time = time.time()
    try:
        log = f'{key.char} pressed at {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}\n'
    except AttributeError:
        log = f'{key} pressed at {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}\n'
    
    try:
        current_key = key.char
        current_word += current_key
        key_usage[current_key] += 1

        if len(current_word) > 5:
            analyze_typing_patterns()

        if check_vulnerable_words(current_word):
            send_reminder("Do not type sensitive information.")

        if avoid_personal_communication(current_word):
            alert_teacher("Avoid personal communication during lessons.")

        if block_non_educational_sites(current_word):
            alert_teacher("Access to non-educational content is blocked.")

        check_lesson_relevance(current_word)
        focus_reminder()
        real_time_threat_detection(current_word)
        data_loss_prevention(current_word)
        behavior_based_access_control()

        with open(LOG_FILE, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"Typing pattern logged: {timestamp} - {current_key}\n")
        log_typing_patterns()

    except AttributeError:
        print(f"Special key pressed: {key}")

def on_release(key):
    global end_time
    if key == Key.esc:
        generate_behavioral_heatmap()
        generate_summary_report()
        generate_pie_chart()
        generate_word_cloud()
        end_time = time.time()
        print("Logging stopped.")
        return False 
    current_key = str(key).replace("'", "")
    key_usage[current_key] += 1

if __name__ == "__main__":
    if get_consent():
        print("Consent given. Starting keylogger...")
        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()
    else:
        print("Consent not given. Exiting...")
# Check if logging occurred and print duration
    if start_time and end_time:
        duration = end_time - start_time
        print(f"Logging duration: {duration:.2f} seconds")
        
        # Write the duration to the log file
        with open(LOG_FILE, "a") as file:
            file.write(f"\nLogging duration: {duration:.2f} seconds\n")


    else:
        print("No keystrokes were logged.")