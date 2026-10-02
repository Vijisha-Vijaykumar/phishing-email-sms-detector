# 🛡️ Phishing Email & SMS Detector

An AI-powered cybersecurity system that detects **phishing emails and SMS messages** by analyzing message content, sender information, URLs, and attachments.

The system combines **NLP-based text analysis** with **URL and attachment security checks** to identify suspicious or potentially malicious messages.

## 🚀 Features

* 📧 **Email Phishing Detection**

  * Analyzes email content and sender information
  * Identifies suspicious patterns commonly found in phishing emails

* 💬 **SMS Phishing Detection**

  * Analyzes SMS messages for phishing and scam indicators
  * Detects suspicious links and social-engineering patterns

* 🔗 **URL Analysis**

  * Examines URLs for suspicious characteristics
  * Checks links for potentially malicious indicators

* 📎 **Attachment Analysis**

  * Performs backend security checks on uploaded attachments
  * Inspects file structure and content for suspicious indicators
  * Supports security analysis without exposing technical tools to the user

* 🤖 **NLP-Based Analysis**

  * Processes message text
  * Identifies phishing-related language and patterns

* 📊 **Risk Assessment**

  * Combines multiple security indicators
  * Provides a phishing/suspicious classification and analysis

## 🏗️ System Architecture

```text
User
  │
  ├── Email
  ├── SMS
  ├── URL
  └── Attachment
        │
        ▼
     Frontend
        │
        ▼
   Python Backend
        │
   ┌────┼─────────────┐
   │    │             │
   ▼    ▼             ▼
 NLP  URL Analysis  Attachment Analysis
   │    │             │
   └────┼─────────────┘
        ▼
  Risk / Phishing Analysis
        │
        ▼
   Result & Explanation
```

## 🛠️ Technologies Used

### Frontend

* HTML
* CSS
* JavaScript

### Backend

* Python
* FastAPI

### AI / Data Science

* Natural Language Processing (NLP)
* Machine Learning
* Text Classification
* Feature Extraction

### Cybersecurity Analysis

* URL security analysis
* File and attachment inspection
* Metadata and structural analysis

## 🔍 How It Works

1. The user submits an **email, SMS, URL, or attachment**.
2. The backend extracts relevant information from the input.
3. NLP techniques analyze the message content.
4. URLs are examined for suspicious characteristics.
5. Attachments are inspected using backend security analysis.
6. The system combines the detected indicators.
7. A final **risk classification and explanation** is presented to the user.

## 🎯 Objective

The goal of this project is to provide a simple security layer that can help users identify potentially dangerous **phishing emails, SMS messages, links, and attachments** before interacting with them.

## ⚠️ Disclaimer

This project is intended for **educational and cybersecurity research purposes**. Detection results should be treated as security indicators rather than a guarantee that a message or file is completely safe or malicious.

## 👩‍💻 Project

**Phishing Email & SMS Detector**

Developed as a student cybersecurity and data science project.

