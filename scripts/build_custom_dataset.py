"""
PhishGuard AI — Build Custom Robustness & Benchmark Dataset
Generates:
1. Controlled phishing templates with:
   - Original
   - Human Paraphrases
   - AI Paraphrases (with generator, prompt_version, human_reviewed)
   - Romanized Hinglish variants
   - Romanized Kanglish variants
2. Hard Negatives:
   - Genuine OTPs
   - Genuine urgent utility notices
3. Near-Miss Pairs:
   - Small wording differences that flip Genuine vs High-risk
4. Email & SMS templates
5. Independent second annotator ratings for Cohen's Kappa evaluation
"""

import os
import json
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CUSTOM_DIR = os.path.join(BASE_DIR, "data", "custom")
os.makedirs(CUSTOM_DIR, exist_ok=True)

ROBUSTNESS_TEMPLATES = [
    {
        "template_id": "T_SMS_KYC_01",
        "category": "Banking/KYC",
        "threat": "Account suspension",
        "urgency": "High",
        "requested_action": "Verify identity",
        "credential_payment_request": "Credential",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "text": "Your HDFC account will be suspended today. Verify KYC immediately: https://hdfc-netbanking-kyc.com/login",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "human_paraphrase",
                "language": "English",
                "text": "Please complete your KYC today, otherwise HDFC Bank will block your account. Link: https://hdfc-netbanking-kyc.com/login",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "ai_paraphrase",
                "language": "English",
                "text": "Action required: KYC verification is pending on your HDFC account. Complete it now at https://hdfc-netbanking-kyc.com/login to avoid service interruption.",
                "risk_label": "High-risk",
                "generator": "offline_gpt4o",
                "prompt_version": "v1.2",
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "hinglish_variant",
                "language": "Hinglish",
                "text": "Aapka HDFC account aaj block ho jayega. Abhi KYC verify karein: https://hdfc-netbanking-kyc.com/login",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "kanglish_variant",
                "language": "Kanglish",
                "text": "Nimma HDFC account ivattu block aaguttade. Eega KYC verify maadi: https://hdfc-netbanking-kyc.com/login",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            }
        ]
    },
    {
        "template_id": "T_SMS_ELEC_02",
        "category": "Utility/Electricity",
        "threat": "Service disconnection",
        "urgency": "High",
        "requested_action": "Call number",
        "credential_payment_request": "Payment",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "text": "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 1,450. Contact power officer at 9823145678 immediately.",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "human_paraphrase",
                "language": "English",
                "text": "Urgent: Power supply will be disconnected tonight at 9:30 PM as previous bill Rs 1,450 is unpaid. Call electricity officer on 9823145678.",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "ai_paraphrase",
                "language": "English",
                "text": "Final warning: Your electrical connection is scheduled for disconnection tonight at 9:30 PM for pending arrears of Rs 1,450. Immediately reach out to 9823145678.",
                "risk_label": "High-risk",
                "generator": "offline_claude35",
                "prompt_version": "v2.0",
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "hinglish_variant",
                "language": "Hinglish",
                "text": "Bijli connection aaj raat 9:30 baje kaat diya jayega kyunki Rs 1450 ka bill pending hai. Turant power officer ko call karein 9823145678.",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "kanglish_variant",
                "language": "Kanglish",
                "text": "Nimma electricity connection ivattu ratri 9:30 ge cut aaguttade pending bill Rs 1450 salavagi. Eega electricity officer ge call maadi 9823145678.",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            }
        ]
    },
    {
        "template_id": "T_SMS_PARCEL_03",
        "category": "Delivery/Courier",
        "threat": "Parcel/Delivery hold",
        "urgency": "Medium",
        "requested_action": "Click link",
        "credential_payment_request": "Payment",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "text": "Your parcel #IND88291 cannot be delivered due to missing house number. Update your delivery address within 24 hours: https://indiapost-parcel-redirection.top/upd",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "human_paraphrase",
                "language": "English",
                "text": "Delivery attempt failed for package #IND88291 because address is incomplete. Please confirm address here: https://indiapost-parcel-redirection.top/upd",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "ai_paraphrase",
                "language": "English",
                "text": "Courier notification: Package #IND88291 is currently on hold at regional depot due to an incomplete delivery address. Update details at https://indiapost-parcel-redirection.top/upd within 24 hours.",
                "risk_label": "High-risk",
                "generator": "offline_gpt4o",
                "prompt_version": "v1.2",
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "hinglish_variant",
                "language": "Hinglish",
                "text": "Aapka parcel #IND88291 deliver nahi ho paya address adhura hone ke karan. 24 ghante me update karein: https://indiapost-parcel-redirection.top/upd",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "kanglish_variant",
                "language": "Kanglish",
                "text": "Nimma parcel #IND88291 deliver aagilla thappu address karana. 24 ghanteyalli update maadi: https://indiapost-parcel-redirection.top/upd",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            }
        ]
    },
    {
        "template_id": "T_SMS_SIM_04",
        "category": "Telecom",
        "threat": "SIM deactivation",
        "urgency": "High",
        "requested_action": "Click link",
        "credential_payment_request": "Credential",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "text": "Important: Your Jio SIM card will be deactivated within 24 hours due to pending Aadhaar biometric verification. Visit: http://192.168.1.55/jio-aadhaar",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "human_paraphrase",
                "language": "English",
                "text": "Your mobile number will stop working tomorrow unless Aadhaar verification is updated at: http://192.168.1.55/jio-aadhaar",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "ai_paraphrase",
                "language": "English",
                "text": "Alert: Telecom regulatory compliance requires mandatory SIM verification. Your line will be suspended in 24 hours. Update now: http://192.168.1.55/jio-aadhaar",
                "risk_label": "High-risk",
                "generator": "offline_gpt4o",
                "prompt_version": "v1.2",
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "hinglish_variant",
                "language": "Hinglish",
                "text": "Aapka Jio SIM card 24 ghante me band ho jayega. Turant Aadhaar KYC complete karein: http://192.168.1.55/jio-aadhaar",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "kanglish_variant",
                "language": "Kanglish",
                "text": "Nimma Jio SIM card 24 ghanteyalli block aaguttade. Aadhaar link madalu illi banni: http://192.168.1.55/jio-aadhaar",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            }
        ]
    },
    {
        "template_id": "T_SMS_TAX_05",
        "category": "Financial/Lure",
        "threat": "Financial loss",
        "urgency": "Medium",
        "requested_action": "Click link",
        "credential_payment_request": "Both",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "text": "Income Tax Department: An approved tax refund of Rs 24,500 has been credited. Confirm your bank account details to claim: https://incometax-refundportal.in/claim",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "human_paraphrase",
                "language": "English",
                "text": "Tax refund of Rs 24,500 is pending release. Please enter your account and IFSC at https://incometax-refundportal.in/claim to receive funds.",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "ai_paraphrase",
                "language": "English",
                "text": "Notification: Your approved income tax rebate of Rs 24,500 is awaiting disbursement. Verify your beneficiary banking details at https://incometax-refundportal.in/claim.",
                "risk_label": "High-risk",
                "generator": "offline_claude35",
                "prompt_version": "v2.0",
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "hinglish_variant",
                "language": "Hinglish",
                "text": "Income Tax Department: Aapka Rs 24,500 ka refund approve ho chuka hai. Account details verify karein: https://incometax-refundportal.in/claim",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "kanglish_variant",
                "language": "Kanglish",
                "text": "Income Tax Department: Nimma Rs 24,500 tax refund approve aagide. Account verify madalu click maadi: https://incometax-refundportal.in/claim",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            }
        ]
    },
    # Hard Negatives
    {
        "template_id": "T_NEG_OTP_06",
        "category": "Transactional",
        "threat": "None",
        "urgency": "High",
        "requested_action": "None",
        "credential_payment_request": "None",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "hard_negative",
                "language": "English",
                "text": "482910 is your OTP for a Rs 3,450.00 transaction at Amazon Pay. Do not share it with anyone. SBI never asks for your OTP.",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": True
            },
            {
                "variant_type": "hard_negative",
                "language": "English",
                "text": "881029 is secret OTP for login to your ICICI iMobile app. Valid for 5 minutes. NEVER disclose OTP to any bank staff or caller.",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": True
            }
        ]
    },
    {
        "template_id": "T_NEG_BILL_07",
        "category": "Utility/Electricity",
        "threat": "Service disconnection",
        "urgency": "High",
        "requested_action": "Pay",
        "credential_payment_request": "None",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "hard_negative",
                "language": "English",
                "text": "Reminder: Rs 850 is outstanding on electricity account ending 4019. Service may be disconnected after 15-Oct if unpaid. Pay through the official BESCOM consumer portal or app. Ignore if already paid.",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": True
            },
            {
                "variant_type": "hard_negative",
                "language": "English",
                "text": "Tata Power notice: Pending bill of Rs 1,120 on CA 900219481 due today. Pay securely through Tata Power mobile app or nearest customer center to avoid late surcharge.",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": True
            }
        ]
    },
    # Near-Miss Pairs
    {
        "template_id": "T_PAIR_OTP_08",
        "category": "Banking/KYC",
        "threat": "None",
        "urgency": "High",
        "requested_action": "Share credential",
        "credential_payment_request": "Credential",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "near_miss_phishing",
                "language": "English",
                "text": "Share the OTP with our executive to complete verification.",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "near_miss_genuine",
                "language": "English",
                "text": "Do not share the OTP with anyone. We will never ask for your OTP.",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": True
            }
        ]
    },
    {
        "template_id": "T_PAIR_APP_09",
        "category": "Banking/KYC",
        "threat": "Account suspension",
        "urgency": "High",
        "requested_action": "Click link",
        "credential_payment_request": "Credential",
        "channel": "SMS",
        "variants": [
            {
                "variant_type": "near_miss_phishing",
                "language": "English",
                "text": "Your account will be blocked today. Verify now: https://bank-secure-update.com",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "near_miss_genuine",
                "language": "English",
                "text": "Your account requires verification. Please open the official bank app manually to complete it.",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": True
            }
        ]
    },
    # Email Templates
    {
        "template_id": "T_EMAIL_SEC_10",
        "category": "Workplace/IT",
        "threat": "Account suspension",
        "urgency": "High",
        "requested_action": "Verify identity",
        "credential_payment_request": "Credential",
        "channel": "Email",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "subject": "Urgent Account Verification Required",
                "body": "Dear Employee,\n\nYour corporate email access will be suspended within 24 hours due to server migration. You must re-authenticate your mailbox immediately using our security portal: https://login.microsoftonline.corp-auth365.net/login\n\nIT Support Team",
                "text": "Subject: Urgent Account Verification Required\nDear Employee, Your corporate email access will be suspended within 24 hours due to server migration. You must re-authenticate your mailbox immediately using our security portal: https://login.microsoftonline.corp-auth365.net/login IT Support Team",
                "sender": "support@corp-auth365.net",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "human_paraphrase",
                "language": "English",
                "subject": "Action Required: Re-verify Mailbox Credentials",
                "body": "Hello team, We are updating IT certificates today. To keep your Outlook account active, verify your login details right now at https://login.microsoftonline.corp-auth365.net/login. Failure will lead to immediate lockout.\nIT Dept",
                "text": "Subject: Action Required: Re-verify Mailbox Credentials\nHello team, We are updating IT certificates today. To keep your Outlook account active, verify your login details right now at https://login.microsoftonline.corp-auth365.net/login. Failure will lead to immediate lockout. IT Dept",
                "sender": "admin@it-desk-notice.com",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "ai_paraphrase",
                "language": "English",
                "subject": "Mandatory Security Update: Validate Your Microsoft 365 Account",
                "body": "Security Alert: All personnel are instructed to complete mandatory identity validation before 5:00 PM today. Unverified accounts will be quarantined. Access the directory at: https://login.microsoftonline.corp-auth365.net/login",
                "text": "Subject: Mandatory Security Update: Validate Your Microsoft 365 Account\nSecurity Alert: All personnel are instructed to complete mandatory identity validation before 5:00 PM today. Unverified accounts will be quarantined. Access the directory at: https://login.microsoftonline.corp-auth365.net/login",
                "sender": "alerts@portal-sec365.com",
                "risk_label": "High-risk",
                "generator": "offline_gpt4o",
                "prompt_version": "v1.2",
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "hinglish_variant",
                "language": "Hinglish",
                "subject": "Zaroori IT Update: Apna Mailbox verify karein",
                "body": "Namaste, aapka company email account aaj sham tak suspend ho sakta hai security update ki wajah se. Turant niche diye link par login karke verify karein: https://login.microsoftonline.corp-auth365.net/login\nDhanyawad, IT Team",
                "text": "Subject: Zaroori IT Update: Apna Mailbox verify karein\nNamaste, aapka company email account aaj sham tak suspend ho sakta hai security update ki wajah se. Turant niche diye link par login karke verify karein: https://login.microsoftonline.corp-auth365.net/login Dhanyawad, IT Team",
                "sender": "it-helpdesk@quick-support.in",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            },
            {
                "variant_type": "kanglish_variant",
                "language": "Kanglish",
                "subject": "Tumba Mukhyavada IT Notice: Nimma Mailbox verify maadi",
                "body": "Namaskara, nimma company email account ivattu sanje suspend aaguttade server update karana. Dayavittu eegale verify maadi: https://login.microsoftonline.corp-auth365.net/login\nDhanyavadagalu, IT Team",
                "text": "Subject: Tumba Mukhyavada IT Notice: Nimma Mailbox verify maadi\nNamaskara, nimma company email account ivattu sanje suspend aaguttade server update karana. Dayavittu eegale verify maadi: https://login.microsoftonline.corp-auth365.net/login Dhanyavadagalu, IT Team",
                "sender": "it-support@corp-update.in",
                "risk_label": "High-risk",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "High-risk",
                "urgent_genuine": False
            }
        ]
    },
    {
        "template_id": "T_EMAIL_STMT_11",
        "category": "Banking/Statement",
        "threat": "None",
        "urgency": "Low",
        "requested_action": "None",
        "credential_payment_request": "None",
        "channel": "Email",
        "variants": [
            {
                "variant_type": "hard_negative",
                "language": "English",
                "subject": "Monthly Account Statement for September 2026",
                "body": "Dear Customer,\n\nYour monthly e-statement for account ending in 1948 is now available. You can view and download your statement anytime by logging into the official netbanking portal or mobile app. Please note that bank officials will never ask for your password or PIN via email.\n\nWarm regards,\nCustomer Care Team",
                "text": "Subject: Monthly Account Statement for September 2026\nDear Customer, Your monthly e-statement for account ending in 1948 is now available. You can view and download your statement anytime by logging into the official netbanking portal or mobile app. Please note that bank officials will never ask for your password or PIN via email. Warm regards, Customer Care Team",
                "sender": "statements@hdfcbank.com",
                "risk_label": "Genuine",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Genuine",
                "urgent_genuine": False
            }
        ]
    },
    {
        "template_id": "T_EMAIL_SUSP_12",
        "category": "Security/Alert",
        "threat": "Financial loss",
        "urgency": "Medium",
        "requested_action": "Click link",
        "credential_payment_request": "None",
        "channel": "Email",
        "variants": [
            {
                "variant_type": "original",
                "language": "English",
                "subject": "Notice: Unrecognized sign-in attempt detected",
                "body": "We noticed a login to your cloud storage from Chrome on Linux (IP: 198.51.100.22). If this was not you, review activity: http://bit.ly/review-cloud-sec",
                "text": "Subject: Notice: Unrecognized sign-in attempt detected\nWe noticed a login to your cloud storage from Chrome on Linux (IP: 198.51.100.22). If this was not you, review activity: http://bit.ly/review-cloud-sec",
                "sender": "notify@account-alerts.com",
                "risk_label": "Suspicious",
                "generator": "human",
                "prompt_version": None,
                "human_reviewed": True,
                "label_2": "Suspicious",
                "urgent_genuine": False
            }
        ]
    }
]

def build_custom_dataset():
    records = []
    msg_counter = 1

    for tmpl in ROBUSTNESS_TEMPLATES:
        t_id = tmpl["template_id"]
        category = tmpl["category"]
        threat = tmpl["threat"]
        urgency = tmpl["urgency"]
        action = tmpl["requested_action"]
        cred_pay = tmpl["credential_payment_request"]
        channel = tmpl["channel"]

        for var in tmpl["variants"]:
            m_id = f"MSG_CUST_{msg_counter:05d}"
            msg_counter += 1

            text = var.get("text", "")
            subject = var.get("subject", "")
            body = var.get("body", text)
            sender = var.get("sender", "")

            # If sender is missing, default empty
            url_present = ("http://" in text) or ("https://" in text) or ("bit.ly" in text)

            rec = {
                "message_id": m_id,
                "channel": channel,
                "text": text,
                "subject": subject,
                "body": body,
                "sender": sender,
                "language": var.get("language", "English"),
                "risk_label": var.get("risk_label", "High-risk"),
                "category": category,
                "threat": threat,
                "urgency": urgency,
                "requested_action": action,
                "credential_payment_request": cred_pay,
                "template_id": t_id,
                "variant_type": var.get("variant_type", "original"),
                "generator": var.get("generator", "human"),
                "prompt_version": var.get("prompt_version"),
                "human_reviewed": var.get("human_reviewed", True),
                "source": "custom_research",
                "source_corpus": "controlled_robustness_suite",
                "label_checked": True,
                "label_2": var.get("label_2", var.get("risk_label")),
                "url_present": url_present,
                "urgent_genuine": var.get("urgent_genuine", False)
            }
            records.append(rec)

    json_path = os.path.join(CUSTOM_DIR, "robustness_suite.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(ROBUSTNESS_TEMPLATES, f, indent=2)

    csv_path = os.path.join(CUSTOM_DIR, "custom_benchmark_records.csv")
    df = pd.DataFrame(records)
    df.to_csv(csv_path, index=False, encoding="utf-8")

    print(f"Generated {len(records)} custom benchmark rows across {len(ROBUSTNESS_TEMPLATES)} templates.")
    print(f"Saved JSON to: {json_path}")
    print(f"Saved CSV to: {csv_path}")

if __name__ == "__main__":
    build_custom_dataset()
