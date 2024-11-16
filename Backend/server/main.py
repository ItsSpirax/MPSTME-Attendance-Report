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
import calendar
import difflib
import json
import os
import re
import math
import random
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


def fun_fact(attendance_df):
    """Generates a fun fact based on the attendance data."""

    if attendance_df.empty:
        return "Uh-oh! Looks like you've missed all the classes this semester. Better luck next time!"

    if (attendance_df["Date"].max() - attendance_df["Date"].min()).days < 30:
        return "Looks like your semester was really short! We'll need a bit more data to give you a fun fact!"

    if attendance_df.shape[0] < 3:
        return "Just getting started? Your attendance is looking good, but let's see how it improves over time!"

    try:
        rand = random.randint(0, 7)

        present_df = attendance_df[attendance_df["Present"] == True]
        total_hours_in_sem_months = (
            attendance_df["Date"].max() - attendance_df["Date"].min()
        ).days * 24
        spent_in_lec = present_df.value_counts().sum()

        if rand == 0:
            streak = 1
            max_streak = 1
            attendance_df["Date"] = attendance_df["Date"].dt.date
            for i in range(1, attendance_df.shape[0]):
                if attendance_df.iloc[i - 1]["Date"] == attendance_df.iloc[i]["Date"]:
                    streak += 1
                    max_streak = max(max_streak, streak)
                else:
                    streak = 1
            return f"🎉 Wow! Your longest streak of attendance is {max_streak} days. You're on fire! Keep that momentum going!"

        if rand == 1:
            date = attendance_df["Date"].dt.date.value_counts().idxmax()
            return f"📅 Looks like {date.strftime('%d %B')} was your busiest day! You attended {attendance_df[attendance_df['Date'] == date].shape[0]} hours of lectures. Phew, that's a lot of learning!"

        if rand == 2:
            ratio = spent_in_lec / total_hours_in_sem_months
            if random.random() < 0.5:
                return f"⏳ Guess what? You've spent a whopping {ratio * 100:.2f}% of your time in class this semester! That's some serious dedication!"
            return f"🎓 You've spent a total of {spent_in_lec} hours in class. That’s like binge-watching your favorite series – but with textbooks!"

        if rand == 3:
            rand_week_month = random.randint(0, 1)
            if rand_week_month == 0:
                present_df["Month"] = present_df["Date"].dt.month
                month = present_df["Month"].value_counts().idxmax()
                return f"🌟 You were the most punctual in {calendar.month_name[month]}! You attended {present_df[present_df['Month'] == month].shape[0]} hours of lectures that month. Keep it up!"
            else:
                present_df["Week"] = present_df["Date"].dt.isocalendar().week
                week = present_df["Week"].value_counts().idxmax()
                return f"⏰ The most punctual week? Week {week}! You attended {present_df[present_df['Week'] == week].shape[0]} hours of lectures. You’re on top of your game!"

        if rand == 4:
            runtimes = {
                "Star Wars Series": 26,
                "Harry Potter Series": 19,
                "Lord of the Rings ": 9,
                "X-Men Series": 22,
                "Suits": 83,
                "Breaking Bad": 62,
                "Game of Thrones": 70,
                "The Office": 99,
            }
            rand_series = random.choice(list(runtimes.keys()))
            if spent_in_lec // runtimes[rand_series] == 0:
                return f"😱 You’ve spent so much time in class, you couldn’t even watch {rand_series} once! Time to cut back on lectures... just kidding!"
            return f"🎬 You could have binge-watched {rand_series} {spent_in_lec // runtimes[rand_series]} times with the hours you've spent in class. That’s some serious classroom dedication!"

        if rand == 5:
            time_taken = {
                "Kashmir to Kanyakumari": 61,
                "Mumbai to Delhi": 25,
                "Mumbai to Bangalore": 18,
                "Mumbai to Pune": 3,
            }
            rand_trip = random.choice(list(time_taken.keys()))
            if spent_in_lec < time_taken[rand_trip]:
                return f"🚗 You haven’t even spent enough time in class to drive from {rand_trip}. Maybe next semester!"
            return f"🌍 In the time you’ve spent in class, you could have driven from {rand_trip} {spent_in_lec // time_taken[rand_trip]} times. Road trip, anyone?"

        if rand == 6:
            if spent_in_lec < 24:
                return f"📚 You’ve spent {spent_in_lec} hours in class. That’s like reading a book for a whole day! Keep up the good work!"

            if spent_in_lec < (20 * 24):
                return f"📚 You’ve spent {spent_in_lec // 24} days attending lectures!"

            if spent_in_lec < (30 * 24):
                return f"📚 You’ve spent {spent_in_lec // 24} days in class. That’s almost a month of pure learning!"

            return f"🗓️ You've spent a total of {spent_in_lec // 24} days in class. That’s a lot!"

        if rand == 7:
            time_to_moon = 69
            if spent_in_lec < time_to_moon:
                time_left = time_to_moon - spent_in_lec
                return f"🌕 You’ve spent {spent_in_lec} hours in class. You're only {time_left} hours away from the moon. Almost there!"
            return f"🚀 You’ve spent {spent_in_lec} hours in class. In fact, you could have traveled to the moon {spent_in_lec // time_to_moon} times! Astronaut-level attendance!"
    except Exception as e:
        return f"🎉 You're doing great! Keep up the good work!"


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

        # Build GitHub graph data
        github_heatmap_data = (
            attendance_df.drop(columns=["Subject"])
            .assign(Date=pd.to_datetime(attendance_df["Date"]).dt.date)
            .groupby("Date", as_index=False)
            .agg(Present=("Present", "sum"))
            .loc[lambda df: df["Present"] != 0]
        )

        if github_heatmap_data.empty:
            github_heatmap_data = {}
        else:
            github_heatmap_data = {
                int(pd.Timestamp(date).timestamp() * 1000): int(count)
                for date, count in zip(
                    github_heatmap_data["Date"], github_heatmap_data["Present"]
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
                "FunFact": fun_fact(attendance_df.copy()),
                "Range": date_range,
                "Data": out_data,
                "RawCSV": [attendance_df.to_csv()],
                "GithubHeatmap": github_heatmap_data,
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
