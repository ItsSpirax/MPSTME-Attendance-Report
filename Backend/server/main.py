# Imports
import base64
import difflib
import json
import os
import re
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from flask import Flask, request, redirect, jsonify
from flask_cors import CORS

# Disable future warnings
warnings.simplefilter(action="ignore", category=FutureWarning)

# Flask app initialization and CORS
app = Flask(__name__)
CORS(app)


# URLs for different portal functionalities
LOGIN_URL = "https://portal.svkm.ac.in/usermgmt/login"
FEEDBACK_URL = "https://portal.svkm.ac.in/MPSTME-NM-M/viewFeedbackDetails"
BRANCH_CHANGE_URL = "https://portal.svkm.ac.in/usermgmt/"
HOMEPAGE_URL = "https://portal.svkm.ac.in/MPSTME-NM-M/homepage"
ATTENDANCE_URL = "https://portal.svkm.ac.in/MPSTME-NM-M/viewDailyAttendanceByStudent"

# Constants
CUTOFF = 0.75
SEMESTER_MAP = {
    "I": "First",
    "II": "Second",
    "III": "Third",
    "IV": "Fourth",
    "V": "Fifth",
    "VI": "Sixth",
    "VII": "Seventh",
    "VIII": "Eighth",
    "IX": "Ninth",
    "X": "Tenth",
    "XI": "Eleventh",
    "XII": "Twelfth",
}

# Load public key for encryption
PUBLIC_KEY = serialization.load_pem_public_key(
    """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsA4VGZEXvEu9TY9HehLS
    mqDyYH37KM7BFd6LTOYZSpctX9d/ZsVOAybI9g2/XXUpP0KLbIp3GJjLOgobCO3J
    aI+3NGKUPUnptKDPlxHaGn/CdueeJIrtDHVJSaTa5kNel75DfQCS14DZvpkgWvov
    uCkj/+62OoxyAZOI34reYJcxCRcWp+3Fo/1KmwdirpcLo254EyN+GORNqxSvDrnT
    eYJ2Sk1NawStX80sbQqN88SKLABrxdZPEB39ZiWi+8GhBIomoCjwBlgM60FwtN+9
    1OPcLF5a2qovViVroHkCTPCMguWhd2/4PgeMLtAkbXwgM5AanMxEREJpFVxG6sgU
    TwIDAQAB
    -----END PUBLIC KEY-----""".encode(
        "utf-8"
    ),
    backend=default_backend(),
)

# Regex for subject code pattern
subject_pattern = re.compile(r"P\d|U\d|T\d")



# Helper function to verify captcha with Cloudflare Turnstile
def cf_turnstile_verify(response, remoteip):
    response_data = {
        "secret": os.environ["TURNSTILE_API_KEY"],
        "response": response,
        "remoteip": remoteip,
    }
    response = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=response_data)
    return json.loads(response.content).get("success", False)


# Encrypts a message using the loaded public key
def encrypt_message(message):
    encoded_message = message.encode("utf-8")
    ciphertext = PUBLIC_KEY.encrypt(
        encoded_message,
        crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


# Extracts user details from BeautifulSoup parsed HTML content
def get_user_details(soup):
    user_details = soup.find_all("div", class_="form-group")
    name = user_details[0].text.split(":")[1].strip().title()
    roll_no = user_details[3].text.split(":")[1].strip()
    program = user_details[1].text.split(":")[1].split("-")[0].strip().title()
    semester = SEMESTER_MAP[user_details[2].text.split(":")[1].strip().split()[1]]
    return name, roll_no, program, semester


# Converts attendance data from HTML into a DataFrame
def get_attendance_df(soup, semester):
    attendance_list = soup.select("div.studAttList tbody tr")
    sapid = attendance_list[0].find_all("td")[1].text

    # Parse attendance entries
    rows = []
    for row in attendance_list:
        tds = row.find_all("td")
        subject = subject_pattern.split(tds[2].text)[0].strip()
        date = pd.to_datetime(tds[5].text + tds[6].text.split("-")[0][:-3], format="%d-%m-%Y%H.%M")
        present = tds[7].text == "P"
        rows.append([subject, date, present])

    # Convert to DataFrame and filter dates
    attendance_df = pd.DataFrame(rows, columns=["Subject", "Date", "Present"])
    last_date = attendance_df["Date"].max()
    start_date = datetime(last_date.year, 6, 15) if semester in ["First", "Third", "Fifth", "Seventh", "Ninth", "Eleventh"] else datetime(last_date.year, 1, 1)
    end_date = datetime(last_date.year, 12, 31) if start_date.month == 6 else datetime(last_date.year, 6, 14)
    attendance_df = attendance_df[(attendance_df["Date"] >= start_date) & (attendance_df["Date"] <= end_date)]

    # Standardize subject names
    subjects = []
    for sub in attendance_df["Subject"].unique():
        for s in subjects:
            if difflib.SequenceMatcher(None, sub, s).ratio() > CUTOFF:
                attendance_df["Subject"] = attendance_df["Subject"].replace(sub, s)
                break
        else:
            subjects.append(sub)

    attendance_df["Subject"] = attendance_df["Subject"].apply(lambda x: difflib.get_close_matches(x, subjects, n=1, cutoff=0.57)[0] if difflib.get_close_matches(x, subjects, n=1, cutoff=CUTOFF) else x)
    return attendance_df.sort_values(by="Date"), sapid


# Parses attendance DataFrame to extract attendance summary
def parse_attendance_df(response_text):
    soup = BeautifulSoup(response_text, "lxml")
    name, roll_no, program, semester = get_user_details(soup)
    attendance_df, sap_id = get_attendance_df(soup, semester)

    # Build attendance summary
    out_data = []
    for subject in attendance_df["Subject"].unique():
        present_count = int(attendance_df[attendance_df["Subject"] == subject]["Present"].sum())
        total_count = int(attendance_df[attendance_df["Subject"] == subject].shape[0])
        percentage = round((present_count / total_count) * 100, 2)
        out_data.append(
            {
                "Subject": subject,
                "Present": present_count,
                "Total": total_count,
                "Percentage": percentage,
            }
        )

    # Build line graph data
    line_graph_data = {}
    for subject in attendance_df["Subject"].unique():
        subject_df = attendance_df[attendance_df["Subject"] == subject]

        if not subject_df.empty:
            subject_df.loc[:, "Date"] = pd.to_datetime(subject_df["Date"]).dt.date
            subject_df = subject_df.sort_values(by="Date")

            subject_df.loc[:, "Percentage"] = round((subject_df["Present"].cumsum() / np.arange(1, len(subject_df) + 1)) * 100, 2)

            line_graph_data[subject] = {int(pd.Timestamp(date).timestamp() * 1000): percentage for date, percentage in zip(subject_df["Date"], subject_df["Percentage"])}
        else:
            line_graph_data[subject] = {}

    # Build GitHub graph data
    github_graph_data = attendance_df.drop(columns=["Subject"]).assign(Date=pd.to_datetime(attendance_df["Date"]).dt.date).groupby("Date", as_index=False).agg(Present=("Present", "sum")).loc[lambda df: df["Present"] != 0]

    if github_graph_data.empty:
        github_graph_data = {}
    else:
        github_graph_data = {int(pd.Timestamp(date).timestamp() * 1000): int(count) for date, count in zip(github_graph_data["Date"], github_graph_data["Present"])}

    date_range = f"{attendance_df['Date'].min().strftime('%d.%m.%Y')} - {attendance_df['Date'].max().strftime('%d.%m.%Y')}" if not attendance_df.empty else "N/A - N/A"
    return {
        "Name": name,
        "SapID": sap_id,
        "RollNo": roll_no,
        "Program": program,
        "Semester": semester,
        "Attendance": {"Range": date_range, "Data": out_data, "LineGraph": line_graph_data, "GithubGraph": github_graph_data},
    }


# Fetches attendance by logging in and parsing attendance page
def get_attendance(username, password):
    s = requests.Session()
    try:
        # Login request
        login_data = {
            "jspname": "nm",
            "username": encrypt_message(username),
            "password": encrypt_message(password),
        }
        r = s.post(LOGIN_URL, data=login_data, timeout=30)
        r.raise_for_status()

        # Check for incorrect credentials
        if r.url == LOGIN_URL:
            raise ValueError("(VE-1) Incorrect username or password. Please double-check and try again.")

        # Handle branch selection if required
        if r.url == BRANCH_CHANGE_URL:
            branches = BeautifulSoup(r.text, "lxml").select("option")[1:]
            selected_branch = next(
                (opt["value"] for opt in branches if opt["value"].split("-")[-1] != username[:4]),
                None,
            )
            if selected_branch:
                r = s.post(BRANCH_CHANGE_URL, data={"appName": selected_branch})
                r.raise_for_status()

        # Final check for successful login
        if r.url != HOMEPAGE_URL and r.url != FEEDBACK_URL:
            raise RuntimeError("(RE-1) An error occurred. Please report this issue to the administrator@spirax.me")

        # Navigate to attendance page
        response = s.get(ATTENDANCE_URL)
        response.raise_for_status()
        return parse_attendance_df(response.text)

    except requests.exceptions.Timeout:
        raise ConnectionError("(CE-1) The SVKM portal is taking too long to respond. It might be down. Please try again later.")
    
    except requests.exceptions.ConnectionError:
        raise ConnectionError("(CE-2) Unable to connect to the SVKM portal. Please try again later.")
    
    except requests.exceptions.HTTPError:
        raise ConnectionError("(CE-3) The SVKM portal seems to be down. Please try again later.")
    
    except Exception as e:
        raise e
    
    finally:
        s.close()


# Validate request for attendance report
def validate_request(request):
    if "cf-turnstile-response" not in request.json or "username" not in request.json or "password" not in request.json:
        raise ValueError("(VE-2) Invalid request. Missing Fields.")

    if not cf_turnstile_verify(request.json["cf-turnstile-response"], request.headers.get("Cf-Connecting-Ip")):
        raise ValueError("(VE-3) Invalid Captcha. Please try again.")

    if not request.json["username"].isdigit() and not 8 <= len(request.json["password"]) <= 20:
        raise ValueError("(VE-4) Invalid username or password. Please double-check and try again.")


# Log User-Agent and any errors
def log(ua, start_time, error=None, type=None):
    try:
        requests.get(f"{os.environ["LOGGING_URL"]}?ua={ua}&time={str(datetime.now() - start_time)}&error={error}&type={type}", timeout=0.5)
    except:
        pass



# Route to redirect to homepage
@app.route("/", methods=["GET"])
def home():
    return redirect("https://attn.spirax.me/", code=301)


# Route to handle attendance report request
@app.route("/v1/getAttendanceReport", methods=["POST"])
def attendance():
    start_time = datetime.now()

    # Handle request and logging
    try:
        validate_request(request)
        attendance = get_attendance(request.json["username"], request.json["password"])
        log(request.headers.get("User-Agent"), start_time)
        return jsonify({"message": "200: Success", "data": attendance})

    except ValueError as ve:
        log(request.headers.get("User-Agent"), start_time, str(ve), type="VE")
        return jsonify({"error": str(ve)}), 400

    except ConnectionError as ce:
        log(request.headers.get("User-Agent"), start_time, str(ce), type="CE")
        return jsonify({"error": str(ce)}), 503

    except RuntimeError as re:
        log(request.headers.get("User-Agent"), start_time, str(re), type="RE")
        return jsonify({"error": str(re)}), 500

    except Exception as e:
        log(request.headers.get("User-Agent"), start_time, str(e), type="GE")
        return jsonify({"error": "(GE-1) An unexpected error occurred. Please try again later."}), 500