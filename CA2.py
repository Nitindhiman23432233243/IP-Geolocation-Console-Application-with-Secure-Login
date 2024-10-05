import bcrypt
import csv
import requests
import re
import logging
from getpass import getpass

# Configure logging to write to a file
logging.basicConfig(
    filename='user_activity.log',  # Log file name
    level=logging.INFO,  # Log level (INFO will track major events)
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format
)

def log_event(event_message, event_type="info"):
    """Logs an event to the log file."""
    if event_type == "info":
        logging.info(event_message)
    elif event_type == "error":
        logging.error(event_message)
    elif event_type == "warning":
        logging.warning(event_message)

def is_email_registered(email):
    try:
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) < 2:
                    continue
                if row[0] == email:
                    return True
    except FileNotFoundError:
        log_event("CSV file not found for user data.", "error")
    return False

def signup():
    print("=== Sign Up ===")
    email = input("Enter your email: ")
    
    # Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("Invalid email format.")
        return
    
    if is_email_registered(email):
        print("Email is already registered.")
        return

    # Get user password and security question
    password = getpass("Enter your password: ")
    if not validate_password(password):
        return
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    security_question = input("Enter your security question (for password recovery): ")
    security_answer = getpass("Enter your security answer: ")

    try:
        with open('regno.csv', mode='a', newline='') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow([email, hashed_password, security_question, security_answer])
        log_event(f"New user signed up: {email}")
        print("User registered successfully!")
    except Exception as e:
        log_event(f"Error during signup: {e}", "error")

def validate_password(password):
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) \
            or not re.search(r"\d", password) or not re.search(r"[!@#\$%\^&\*]", password):
        print("Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.")
        return False
    return True

def authenticate_user(email, password):
    try:
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) < 2:
                    continue
                if row[0] == email:
                    if bcrypt.checkpw(password.encode('utf-8'), row[1].encode('utf-8')):
                        log_event(f"Successful login for user: {email}")
                        return True
                    else:
                        log_event(f"Failed login attempt (wrong password) for user: {email}", "warning")
                        return False
            log_event(f"Failed login attempt (email not found): {email}", "warning")
    except Exception as e:
        log_event(f"Error during login: {e}", "error")
    return False

def forgot_password():
    print("=== Forgot Password ===")
    email = input("Enter your registered email: ")

    try:
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) < 4:
                    continue
                if row[0] == email:
                    log_event(f"Password reset requested for user: {email}")
                    answer = getpass(f"Answer to your security question: {row[2]} ")
                    if answer == row[3]:
                        new_password = getpass("Enter new password: ")
                        if validate_password(new_password):
                            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                            update_password(email, hashed_password)
                            log_event(f"Password reset successful for user: {email}")
                            print("Password reset successful.")
                        return
                    else:
                        log_event(f"Failed password reset attempt (wrong answer) for user: {email}", "warning")
                        print("Incorrect answer to the security question.")
                        return
            log_event(f"Password reset attempt failed (email not found): {email}", "warning")
            print("Email not found.")
    except Exception as e:
        log_event(f"Error during password reset: {e}", "error")

def update_password(email, new_hashed_password):
    try:
        rows = []
        with open('regno.csv', mode='r') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if len(row) >= 2 and row[0] == email:
                    row[1] = new_hashed_password
                rows.append(row)
        
        with open('regno.csv', mode='w', newline='') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerows(rows)
    except Exception as e:
        log_event(f"Error updating password for user: {email}: {e}", "error")

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            public_ip = response.json()['ip']
            log_event(f"Public IP fetched successfully: {public_ip}")
            return public_ip
        else:
            log_event("Failed to fetch public IP.", "error")
            print("Unable to fetch your IP address. Please check your internet connection.")
    except Exception as e:
        log_event(f"Error fetching public IP: {e}", "error")
        print(f"Error fetching IP: {e}")
    return None

def get_geolocation(ip_address):
    try:
        api_url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                log_event(f"Geolocation fetched for IP: {ip_address}")
                print(f"Country: {data['country']}")
                print(f"City: {data['city']}")
                print(f"Region: {data['regionName']}")
                print(f"Latitude: {data['lat']}")
                print(f"Longitude: {data['lon']}")
                print(f"Timezone: {data['timezone']}")
                print(f"ISP: {data['isp']}")
            else:
                log_event(f"Failed to fetch geolocation for IP: {ip_address}", "warning")
                print("Geolocation data not found for this IP.")
        else:
            log_event("Error fetching geolocation data.", "error")
            print("Error fetching geolocation data.")
    except Exception as e:
        log_event(f"Error fetching geolocation: {e}", "error")
        print(f"Error fetching geolocation: {e}")

def main():
    print("=== Welcome to the IP Geolocation App ===")
    while True:
        choice = input("1. Sign Up\n2. Log In\n3. Forgot Password\n4. Exit\nEnter your choice: ")

        if choice == '1':
            signup()
        elif choice == '2':
            email = input("Enter your email: ")
            password = getpass("Enter your password: ")

            if authenticate_user(email, password):
                print("Login successful!")
                while True:
                    ip_choice = input("Enter an IP address or press Enter to use your own IP: ")
                    if not ip_choice:
                        ip_choice = get_public_ip()
                        if not ip_choice:
                            break
                    get_geolocation(ip_choice)
                    break
            else:
                print("Login failed. Please check your credentials.")
        elif choice == '3':
            forgot_password()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()


# In[ ]:





# In[ ]:




