import base64
import difflib
import json
import os
import re
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
    "attendance": "https://portal.svkm.ac.in/MPSTME-NM-M/viewDailyAttendanceByStudent",
    "branch_select": "https://portal.svkm.ac.in/usermgmt/",
    "feedback": "https://portal.svkm.ac.in/MPSTME-NM-M/viewFeedbackDetails",
    "home": "https://portal.svkm.ac.in/MPSTME-NM-M/homepage",
    "login": "https://portal.svkm.ac.in/usermgmt/login",
}


# Helper functions
def turnstile_verify(request):
    """Verifies the Cloudflare Turnstile captcha response."""
    if "cf-turnstile-response" not in request.json:
        raise ValueError("(VE-7) Missing captcha response. Please try again.")

    data = {
        "secret": os.environ["TURNSTILE_SECRET"],
        "response": request.json["cf-turnstile-response"],
        "remoteip": request.headers.get("Cf-Connecting-Ip"),
    }

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise ValueError(f"(VE-8) Captcha verification failed: {e}") from e

    if not json.loads(response.content).get("success"):
        raise ValueError("(VE-9) Captcha verification failed.")

    return True


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


def validate_request(request):
    """Validates the incoming request for required fields."""
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        raise ValueError("(VE-1) Missing username or password.")

    if not username.isdigit() or not 8 <= len(password) <= 16:
        raise ValueError("(VE-2) Invalid username or password.")

    return username, password


def log(ua, start_time, error="None"):
    """Logs the message with a timestamp."""
    try:
        requests.get(
            f"{os.environ["LOGGING_URL"]}?ua={ua}&time={str(datetime.now() - start_time)}&error={error}",
            timeout=0.5,
        )
    except:
        pass


# Main functions
def get_user_details(soup):
    """Extracts user details from BeautifulSoup parsed HTML content."""
    try:
        user_details = soup.find_all("div", class_="form-group")
        name = user_details[0].text.split(":")[1].strip().title()
        roll_no = user_details[3].text.split(":")[1].strip()
        program = user_details[1].text.split(":")[1].split("-")[0].strip().title()
        semester = SEMESTER_MAP[user_details[2].text.split(":")[1].strip().split()[1]]
        return name, roll_no, program, semester
    except Exception as e:
        raise ValueError(f"(VE-4) Failed to extract user details: {e}") from e


def get_attendance_df(soup, semester):
    """Converts attendance data from HTML into a DataFrame."""
    try:
        attendance_list = soup.select("div.studAttList tbody tr")
        sapid = attendance_list[0].find_all("td")[1].text

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
        return attendance_df.sort_values(by="Date"), sapid

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
        if r.url != SVKM_URLS["home"] and r.url != SVKM_URLS["feedback"]:
            raise RuntimeError(
                f"(RE-1) An error occurred during login. {r.url} : {r.status_code}"
            )

        # Navigate to attendance page
        response = s.get(SVKM_URLS["attendance"])
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "lxml")

    except requests.exceptions.Timeout:
        raise ConnectionError(
            "(CE-1) The SVKM portal is taking too long to respond. It might be down. Please try again later."
        )

    except requests.exceptions.ConnectionError:
        raise ConnectionError(
            "(CE-2) Unable to connect to the SVKM portal. Please try again later."
        )

    except requests.exceptions.HTTPError:
        raise ConnectionError(
            "(CE-3) The SVKM portal returned an error. Please try again later."
        )

    finally:
        s.close()

    return generate_report(soup)


# Route to redirect to homepage
@app.route("/", methods=["GET"])
def home():
    return redirect("https://attn.spirax.me/", code=301)


# Route to handle attendance report request
@app.route("/v1/getAttendanceReport", methods=["POST"])
def attendance():

    # Website sends a ping request onload to warm up the function
    if request.args.get("ping") == "true":
        return jsonify({"message": "Pong"})

    start_time = datetime.now()

    try:
        turnstile_verify(request)
        username, password = validate_request(request)
        attendance = get_attendance(username, password)
        log(request.headers.get("User-Agent"), start_time)
        return jsonify({"message": "Success", "data": attendance})

    except ValueError as ve:
        log(request.headers.get("User-Agent"), start_time, str(ve))
        return jsonify({"error": str(ve)}), 400

    except ConnectionError as ce:
        log(request.headers.get("User-Agent"), start_time, str(ce))
        return jsonify({"error": str(ce)}), 503

    except RuntimeError as re:
        log(request.headers.get("User-Agent"), start_time, str(re))
        return jsonify({"error": str(re)}), 500

    except Exception as e:
        log(request.headers.get("User-Agent"), start_time, str(e))
        return jsonify({"error": f"(GE-1) An unexpected error occurred: {e}"}), 500
