# IDS-System

> The IDS-System can be used in the following scenarios:

1. Real-Time System Monitoring

Continuously monitors system activities in the background

Tracks unusual or suspicious behavior in real time

2. Detection of Unauthorized or Suspicious Activity

Identifies abnormal system behavior and potential intrusion attempts

Helps detect security threats before they cause serious damage

3. Instant Telegram Notifications

Sends immediate alerts to the administrator via a Telegram bot

Allows remote monitoring without being physically present on the system

4. Local Audio Alert System

Triggers a beep alarm on the system when suspicious activity is detected

Provides instant on-site awareness in offices, labs, or secure environments

5. Security for Personal and Small-Scale Systems

Suitable for personal computers, small servers, and local environments

Adds an extra layer of security with minimal resource usage

6. Educational and Learning Purposes

Useful for cybersecurity students and beginners

Demonstrates a practical implementation of an Intrusion Detection System

7. Faster Admin Response to Threats

Real-time alerts help administrators take quick action

Reduces response time during security incidents

![License](https://img.shields.io/badge/license-MIT-green) ![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Language](https://img.shields.io/badge/language-Python-yellow) ![GitHub](https://img.shields.io/badge/GitHub-eisaalsa555/IDS-System-black?logo=github) ![Build Status](https://img.shields.io/github/actions/workflow/status/eisaalsa555/IDS-System/ci.yml?branch=main)

## 📋 Table of Contents

- [Installation](#installation)

## ℹ️ Project Information

- **👤 Author:** eisaalsa555
- **📦 Version:** 1.0.0
- **📄 License:** MIT
- **🌐 Website:** [https://mohd-eisa-bey.netlify.app](https://mohd-eisa-bey.netlify.app)
- **📂 Repository:** [https://github.com/eisaalsa555/IDS-System](https://github.com/eisaalsa555/IDS-System)
- **🏷️ Keywords:** Intrusion Detection System, IDS, Cyber Security

## Installation

# 1️⃣ Clone the Repository

# First, clone the public GitHub repository to your local system:
```
git clone https://github.com/eisaalsa555/IDS-System.git
```

# Move into the project directory:
```
cd IDS-System
```
## 2️⃣ Create and Activate Virtual Environment (Recommended)

#Creating a virtual environment helps manage dependencies cleanly.
```
python -m venv venv
```

3 Activate the virtual environment:

#Windows
````
venv\Scripts\activate
````

#Linux / macOS
```
source venv/bin/activate
````
## 3️⃣ Install Required Dependencies

# Install all required Python packages:
```
pip install -r requirements.txt
```
## 4️⃣ Configure Telegram Bot

Before running the system, configure your Telegram bot:

Create a Telegram bot using BotFather

Copy your Bot Token

Get your Admin Chat ID

Add these details inside the configuration file (or script variables)

This step is required for receiving alert notifications.

# 5️⃣ Run the IDS System

## Start the Intrusion Detection System using:
```
python main.py
```
## 6️⃣ System Behavior After Running

Once running:

The system continuously monitors activity

Detects unusual or suspicious behavior

Sends instant alerts to the admin via Telegram

Triggers a local beep alarm on detection

## ⚠️ Notes
Make sure Python 3.8 or higher is installed

The repository must be public for cloning

Telegram bot configuration is mandatory for alerts

