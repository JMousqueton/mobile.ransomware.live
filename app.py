from flask import Flask, render_template, jsonify
import json
from datetime import datetime
import pycountry
import hashlib
import os
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)

victims = []
hudsonrock_data = []
ttps_data = []
yara_directories = []
malware_dir = "/var/www/ransomware-ng/import/Malware"

def load_data():
    global victims, hudsonrock_data, ttps_data, yara_directories

    with open('./data/victims.json', 'r') as f:
        victims = json.load(f)
        victims = victims[-100:][::-1]
    with open('./data/hudsonrock.json', 'r') as f:
            hudsonrock_data = json.load(f)
    with open('./data/ttps.json', 'r') as f:
        ttps_data = json.load(f)    
    yara_directories = [d.lower() for d in os.listdir(malware_dir) if os.path.isdir(os.path.join(malware_dir, d))]
    # Print the update time with a timestamp
    #print(f'Data updated at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

# Load the data initially when the server starts
load_data()


# Configure and start the scheduler
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(func=load_data, trigger="interval", minutes=15)
scheduler.start()

# Ensure the scheduler shuts down when the app does
atexit.register(lambda: scheduler.shutdown())

# Convert discovered and published dates to datetime objects
for victim in victims:

    dt_object = datetime.strptime(victim['discovered'], '%Y-%m-%d %H:%M:%S.%f')
    victim['discovered'] = datetime.strptime(victim['discovered'], '%Y-%m-%d %H:%M:%S.%f')
    victim['published'] = datetime.strptime(victim['published'], '%Y-%m-%d %H:%M:%S.%f')
    
    victim['formated_date'] = dt_object.strftime('%Y-%m-%d %H:%M')

    country = pycountry.countries.get(alpha_2=victim['country'])
    victim['country_name'] = country.name if country else victim['country']

    group_name = victim['group_name'].lower()
    if group_name in yara_directories:
        victim['has_yara'] = True 
    else:
        victim['has_yara'] =  False
 
    # Check if the website is valid, if not prepend http://
    if victim['website'] and not victim['website'].startswith(('http://', 'https://')):
       victim['website'] = 'http://' + victim['website']

    # Calculate the MD5 hash of the post_url for screenshot checking
    post_url_md5 = hashlib.md5(victim['post_url'].encode()).hexdigest()
    victim['post_url_md5'] = post_url_md5

    # Define the path to the screenshot
    screenshot_path = f'/var/www/ransomware-ng/docs/screenshots/posts/{post_url_md5}.png'
    
    # Check if the screenshot exists
    victim['has_screenshot'] = os.path.exists(screenshot_path)

    # Add flag to indicate infostealer info based on hudsonrock.json
    website_domain = victim['website'].replace('http://', '').replace('https://', '').split('/')[0]


    if website_domain in hudsonrock_data:
        infostealer_data = hudsonrock_data[website_domain]
        if infostealer_data['employees'] > 0 or infostealer_data['users'] > 1:
            victim['has_infostealer_info'] = True
            victim['infostealer_data'] = infostealer_data
        else:
            victim['has_infostealer_info'] = False
    else:
        victim['has_infostealer_info'] = False


    # Check if the group_name exists in ttps.json and pass TTP data
    for ttp in ttps_data:
        if ttp['group_name'] == victim['group_name'].lower():
            victim['has_ttps'] = True
            victim['ttps_data'] = ttp
            break
    else:
        victim['has_ttps'] = False
        victim['ttps_data'] = None

@app.route('/')
def index():
    #load_data()
    return render_template('index.html', victims=victims)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
