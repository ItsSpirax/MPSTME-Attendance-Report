"""
Developed by Adith
GitHub Repository: https://github.com/ItsSpirax/MPSTME-Attendance-Report

Description:
This Flask application facilitates the retrieval and analysis of attendance 
data from the SVKM portal. It provides users with detailed attendance 
reports, including subject-wise statistics, low-attendance warnings, and 
data visualization-friendly formats such as line graphs and GitHub-style 
activity heatmaps.

Key Features:
- Secure credential handling using RSA encryption.
- Captcha validation using Cloudflare Turnstile.
- Subject standardization and semester-specific data filtering.
- Attendance percentage analysis with actionable insights 
  (e.g., low-attendance deltas).

License:
MIT License - Open source and available for use under the terms 
specified in the license.
"""

import base64
import difflib
import json
import os
import re
import math
from datetime import datetime

import pandas as pd
import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from flask import Flask, request, redirect, jsonify
from flask_cors import CORS


# Initializing Flask app
app = Flask(__name__)
CORS(app)


# Constants
DIFFLIB_RATIO_THRESHOLD = 0.75

PUBLIC_KEY = serialization.load_pem_public_key(
    b"""
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsA4VGZEXvEu9TY9HehLS
    mqDyYH37KM7BFd6LTOYZSpctX9d/ZsVOAybI9g2/XXUpP0KLbIp3GJjLOgobCO3J
    aI+3NGKUPUnptKDPlxHaGn/CdueeJIrtDHVJSaTa5kNel75DfQCS14DZvpkgWvov
    uCkj/+62OoxyAZOI34reYJcxCRcWp+3Fo/1KmwdirpcLo254EyN+GORNqxSvDrnT
    eYJ2Sk1NawStX80sbQqN88SKLABrxdZPEB39ZiWi+8GhBIomoCjwBlgM60FwtN+9
    1OPcLF5a2qovViVroHkCTPCMguWhd2/4PgeMLtAkbXwgM5AanMxEREJpFVxG6sgU
    TwIDAQAB
    -----END PUBLIC KEY-----""",
    backend=default_backend(),
)

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

SUBJECT_CODE_REGEX = re.compile(r"P\d|U\d|T\d")

SVKM_URLS = {
    "branch_select": "https://portal.svkm.ac.in/usermgmt/",
    "home": r"https://portal\.svkm\.ac\.in/.*/(viewFeedbackDetails|homepage)",
    "college": r"https://portal\.svkm\.ac\.in/(.+)/",
    "login": "https://portal.svkm.ac.in/usermgmt/login",
}


# Helper functions
def turnstile_verify(req):
    """Verifies the Cloudflare Turnstile captcha response."""
    if "captcha" not in req.json:
        raise ValueError("(VE-7) Missing captcha response. Please try again.")

    data = {
        "secret": os.environ["TURNSTILE_SECRET"],
        "response": req.json["captcha"],
        "remoteip": req.headers.get("Cf-Connecting-Ip"),
    }

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            timeout=10,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ValueError(f"(VE-8) Captcha verification failed: {e}") from e

    if not json.loads(response.content).get("success"):
        raise ValueError("(VE-9) Captcha verification failed. Please try again.")

    return True


def encrypt_message(message):
    """Encrypts the message using the public key."""
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


def validate_request(req):
    """Validates the incoming request for required fields."""
    username = req.json.get("username")
    password = req.json.get("password")

    if not username or not password:
        raise ValueError("(VE-1) Missing username or password.")

    if not username.isdigit() or not 8 <= len(password) <= 16:
        raise ValueError("(VE-2) Invalid username or password.")

    return username, password


def log(ua, start_time, error="None"):
    """Logs the message with a timestamp."""
    try:
        log_url = os.environ["LOGGING_URL"]
        if not log_url:
            return
        time_taken = str(datetime.now() - start_time)
        requests.get(
            f"{log_url}?ua={ua}&time={time_taken}&error={error}",
            timeout=0.5,
        )
    except Exception:
        pass


# Main functions
def get_user_details(soup):
    """Extracts user details from BeautifulSoup parsed HTML content."""
    try:
        user_details = soup.find_all("div", class_="form-group")
        return (
            user_details[0].text.split(":")[1].strip().title(),  # Name
            user_details[3].text.split(":")[1].strip(),  # Roll No
            user_details[1].text.split(":")[1].split("-")[0].strip().title(),  # Program
            SEMESTER_MAP[
                user_details[2].text.split(":")[1].strip().split()[1]
            ],  # Semester
        )
    except Exception as e:
        raise ValueError(f"(VE-4) Failed to extract user details: {e}") from e


def get_attendance_df(soup, semester):
    """Converts attendance data from HTML into a DataFrame."""
    try:
        attendance_list = soup.select("div.studAttList tbody tr")

        # Parse attendance entries
        rows = []
        for row in attendance_list:
            tds = row.find_all("td")
            subject = SUBJECT_CODE_REGEX.split(tds[2].text)[0].strip()
            date = pd.to_datetime(
                tds[5].text + tds[6].text.split("-")[0][:-3], format="%d-%m-%Y%H.%M"
            )
            present = tds[7].text == "P"
            rows.append([subject, date, present])

        # Convert to DataFrame and filter dates
        attendance_df = pd.DataFrame(rows, columns=["Subject", "Date", "Present"])

        last_date = attendance_df["Date"].max()
        start_date = (
            datetime(last_date.year, 6, 15)
            if semester in ["First", "Third", "Fifth", "Seventh", "Ninth", "Eleventh"]
            else datetime(last_date.year, 1, 1)
        )
        end_date = (
            datetime(last_date.year, 12, 31)
            if start_date.month == 6
            else datetime(last_date.year, 6, 14)
        )
        attendance_df = attendance_df[
            (attendance_df["Date"] >= start_date) & (attendance_df["Date"] <= end_date)
        ]

        # Standardize subject names
        subjects = []
        for sub in attendance_df["Subject"].unique():
            for s in subjects:
                if (
                    difflib.SequenceMatcher(None, sub, s).ratio()
                    > DIFFLIB_RATIO_THRESHOLD
                ):
                    attendance_df["Subject"] = attendance_df["Subject"].replace(sub, s)
                    break
            else:
                subjects.append(sub)

        attendance_df["Subject"] = attendance_df["Subject"].apply(
            lambda x: (
                difflib.get_close_matches(
                    x, subjects, n=1, cutoff=DIFFLIB_RATIO_THRESHOLD
                )[0]
                if difflib.get_close_matches(
                    x, subjects, n=1, cutoff=DIFFLIB_RATIO_THRESHOLD
                )
                else x
            )
        )
        return (
            attendance_df.sort_values(by="Date"),
            attendance_list[0].find_all("td")[1].text,
        )

    except Exception as e:
        raise ValueError(f"(VE-5) Failed to extract attendance data: {e}") from e


def generate_report(soup):
    """Generates attendance summary."""
    name, roll_no, program, semester = get_user_details(soup)
    attendance_df, sap_id = get_attendance_df(soup, semester)

    try:
        # Build attendance summary
        out_data = []
        for subject in attendance_df["Subject"].unique():
            present_count = int(
                attendance_df[attendance_df["Subject"] == subject]["Present"].sum()
            )
            total_count = int(
                attendance_df[attendance_df["Subject"] == subject].shape[0]
            )
            percentage = round((present_count / total_count) * 100, 2)
            if percentage < 80:
                delta_to_eighty = -math.ceil(
                    (round(0.8 * total_count, 2) - present_count) / 0.2
                )
            else:
                delta_to_eighty = math.floor(
                    (present_count - round(0.8 * total_count, 2)) / 0.8
                )
            out_data.append(
                {
                    "Subject": subject,
                    "Present": present_count,
                    "Total": total_count,
                    "Percentage": percentage,
                    "DeltaToEighty": delta_to_eighty,
                }
            )

        # Build line graph data
        line_graph_data = {}
        for subject in attendance_df["Subject"].unique():
            subject_df = attendance_df[attendance_df["Subject"] == subject]

            if not subject_df.empty:
                subject_df.loc[:, "Date"] = pd.to_datetime(subject_df["Date"]).dt.date
                subject_df = subject_df.sort_values(by="Date")

                subject_df.loc[:, "Percentage"] = round(
                    (
                        subject_df["Present"].cumsum()
                        / list(range(1, len(subject_df) + 1))
                    )
                    * 100,
                    2,
                )

                line_graph_data[subject] = {
                    int(pd.Timestamp(date).timestamp() * 1000): percentage
                    for date, percentage in zip(
                        subject_df["Date"], subject_df["Percentage"]
                    )
                }
            else:
                line_graph_data[subject] = {}

        # Build GitHub graph data
        github_graph_data = (
            attendance_df.drop(columns=["Subject"])
            .assign(Date=pd.to_datetime(attendance_df["Date"]).dt.date)
            .groupby("Date", as_index=False)
            .agg(Present=("Present", "sum"))
            .loc[lambda df: df["Present"] != 0]
        )

        if github_graph_data.empty:
            github_graph_data = {}
        else:
            github_graph_data = {
                int(pd.Timestamp(date).timestamp() * 1000): int(count)
                for date, count in zip(
                    github_graph_data["Date"], github_graph_data["Present"]
                )
            }

        date_range = (
            f"{attendance_df['Date'].min().strftime('%d.%m.%Y')} - {attendance_df['Date'].max().strftime('%d.%m.%Y')}"
            if not attendance_df.empty
            else "N/A - N/A"
        )
        return {
            "Name": name,
            "SapID": sap_id,
            "RollNo": roll_no,
            "Program": program,
            "Semester": semester,
            "Attendance": {
                "Range": date_range,
                "Data": out_data,
                "RawData": attendance_df.to_dict(orient="records"),
                "LineGraph": line_graph_data,
                "GithubGraph": github_graph_data,
            },
        }
    except Exception as e:
        raise ValueError(f"(VE-6) Failed to generate attendance report: {e}") from e


def get_attendance(username, password):
    """Fetches attendance by logging in and parsing the attendance page."""
    s = requests.Session()
    try:
        # Login request
        login_data = {
            "jspname": "nm",
            "username": encrypt_message(username),
            "password": encrypt_message(password),
        }
        r = s.post(SVKM_URLS["login"], data=login_data, timeout=30)
        r.raise_for_status()

        # Check for incorrect credentials
        if r.url == SVKM_URLS["login"]:
            raise ValueError(
                "(VE-3) Incorrect username or password. Please check and try again."
            )

        # Handle branch selection if required
        if r.url == SVKM_URLS["branch_select"]:
            branches = BeautifulSoup(r.text, "lxml").select("option")[1:]
            selected_branch = next(
                (
                    opt["value"]
                    for opt in branches
                    if opt["value"].split("-")[-1] != username[:4]
                ),
                None,
            )
            if selected_branch:
                r = s.post(
                    SVKM_URLS["branch_select"], data={"appName": selected_branch}
                )
                r.raise_for_status()

        # Final check for successful login
        if re.match(SVKM_URLS["home"], r.url) is None:
            raise RuntimeError(
                f"(RE-1) An error occurred during login. {r.url} : {r.status_code}"
            )

        college_name = re.match(SVKM_URLS["college"], r.url).group(1)
        if college_name != "MPSTME-NM-M":
            raise ValueError(
                f"(VE-10) Unsupported College: {college_name}. To request support, please submit an issue on our GitHub repository."
            )

        # Navigate to attendance page
        response = s.get(
            f"https://portal.svkm.ac.in/{college_name}/viewDailyAttendanceByStudent"
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "lxml")

    except requests.exceptions.Timeout as e:
        raise ConnectionError(
            "(CE-1) The SVKM portal is taking too long to respond. It might be down. Please try again later."
        ) from e

    except requests.exceptions.ConnectionError as e:
        raise ConnectionError(
            "(CE-2) Unable to connect to the SVKM portal. Please try again later."
        ) from e

    except requests.exceptions.HTTPError as e:
        raise ConnectionError(f"(CE-3) The SVKM portal returned an error: {e}") from e

    finally:
        s.close()

    return generate_report(soup)


@app.route("/", methods=["GET"])
def home():
    """Redirects to the homepage."""
    return redirect(os.environ["WEBSITE_URL"], code=301)


@app.route("/v1/getAttendanceReport", methods=["POST"])
def attendance():
    """Handles the attendance report request."""

    # Website sends a ping request onload to warm up the function
    if request.args.get("ping") == "true":
        return jsonify({"message": "Pong"})

    start_time = datetime.now()

    try:
        turnstile_verify(request)
        username, password = validate_request(request)
        data = get_attendance(username, password)
        log(request.headers.get("User-Agent"), start_time, "None")
        return jsonify({"message": "Success", "data": data})

    except ValueError as value_err:
        log(request.headers.get("User-Agent"), start_time, str(value_err))
        return jsonify({"error": str(value_err)}), 400

    except ConnectionError as connection_err:
        log(request.headers.get("User-Agent"), start_time, str(connection_err))
        return jsonify({"error": str(connection_err)}), 503

    except RuntimeError as runtime_err:
        log(request.headers.get("User-Agent"), start_time, str(runtime_err))
        return jsonify({"error": str(runtime_err)}), 500

    except Exception as err:
        log(request.headers.get("User-Agent"), start_time, str(err))
        return jsonify({"error": f"(GE-1) An unexpected error occurred: {err}"}), 500
