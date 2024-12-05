"""
Developed by Adith Ramakrishna
GitHub Repository: https://github.com/ItsSpirax/MPSTME-Attendance-Report

Description:
This Flask application facilitates the retrieval and analysis of attendance 
data from the SVKM portal. It provides users with detailed attendance 
reports, low-attendance warnings, interesting facts, and data 
visualization-friendly formats such as GitHub Themed heatmaps.

Key Features:
- Secure credential handling using RSA encryption.
- Captcha validation using Cloudflare Turnstile.
- Subject standardization and semester-specific data filtering.
- Attendance percentage analysis with actionable insights 
  (e.g., low-attendance deltas).

License:
GNU General Public License v3.0
Use, modify, and distribute the code freely, provided the license is included.
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
from num2words import num2words


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


def log(ua, start_time, error="No Error"):
    """Logs the message with a timestamp."""
    try:
        log_url = os.environ["LOGGING_URL"]
        if not log_url:
            return
        time_taken = str(round((datetime.now() - start_time).total_seconds(), 2))
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
    if attendance_df.shape[0] < 7:
        return "Just getting started? Your attendance is looking good, but let's see how it improves over time!"

    if (attendance_df["Date"].max() - attendance_df["Date"].min()).days < 15:
        return "Looks like your semester just started! Keep up the good work and check back for more insights soon."

    try:
        rand = random.randint(0, 9)
        present_df = attendance_df[attendance_df["Present"] == True].copy()
        total_hours_in_semester = (
            attendance_df["Date"].max() - attendance_df["Date"].min()
        ).days * 24
        hours_in_lectures = present_df.shape[0]

        if rand == 0:
            streak, max_streak = 1, 1
            present_df["Date"] = present_df["Date"].dt.date
            present_df = (
                present_df.sort_values("Date")
                .reset_index(drop=True)
                .drop_duplicates(subset="Date")
            )
            for i in range(1, present_df.shape[0]):
                if (
                    present_df.iloc[i]["Date"] - present_df.iloc[i - 1]["Date"]
                ).days == 1:
                    streak += 1
                    max_streak = max(max_streak, streak)
                else:
                    streak = 1
            return f"🎉 Wow! Your longest streak of attendance is {max_streak} days. Keep that momentum going!"

        if rand == 1:
            busiest_date = attendance_df["Date"].dt.date.value_counts().idxmax()
            lectures_on_date = attendance_df[
                attendance_df["Date"].dt.date == busiest_date
            ].shape[0]
            return f"📅 Looks like {busiest_date.strftime('%d %B')} was your busiest day with {lectures_on_date} hours of lectures. Great effort!"

        if rand == 2:
            attendance_ratio = hours_in_lectures / total_hours_in_semester
            if random.random() < 0.5:
                return f"⏳ You've spent {attendance_ratio * 100:.2f}% of your time in lectures this semester. Amazing dedication!"
            return f"🎓 You've attended {hours_in_lectures} hours of lectures. That’s like binge-watching your favorite series – but with learning!"

        if rand == 3:
            if random.random() < 0.5:
                most_punctual_month = (
                    present_df["Date"].dt.month.value_counts().idxmax()
                )
                month_name = calendar.month_name[most_punctual_month]
                hours_in_month = present_df[
                    present_df["Date"].dt.month == most_punctual_month
                ].shape[0]
                return f"🌟 You were most punctual in {month_name} with {hours_in_month} hours of lectures. Keep it up!"

            most_punctual_week = (
                present_df["Date"].dt.isocalendar().week.value_counts().idxmax()
            )
            hours_in_week = present_df[
                present_df["Date"].dt.isocalendar().week == most_punctual_week
            ].shape[0]
            return f"⏰ Your most punctual week was Week {most_punctual_week}, with {hours_in_week} hours of lectures. Well done!"

        if rand == 4:
            runtimes = {
                "the Star Wars movies": 26,
                "the Harry Potter series": 19,
                "the Lord of the Rings movies": 9,
                "the X-Men franchise": 22,
                "Suits": 83,
                "Breaking Bad": 62,
                "Game of Thrones": 70,
                "The Office": 99,
                "Friends": 89,
                "Stranger Things": 35,
            }
            random_series, runtime = random.choice(list(runtimes.items()))
            binge_count = hours_in_lectures // runtime
            if binge_count > 0:
                return f"🎬 You could have binge-watched {random_series} {num2words(binge_count).title()} times with your lecture hours. Impressive focus!"
            return f"😱 You’ve spent so much time in lectures, you couldn’t even finish {random_series} once!"

        if rand == 5:
            travel_times = {
                "Kashmir to Kanyakumari": 61,
                "Mumbai to Delhi": 25,
                "Mumbai to Bangalore": 18,
                "Mumbai to Pune": 3,
                "Mumbai to Goa": 12,
                "Mumbai to Ahmedabad": 10,
                "Mumbai to Jaipur": 21,
            }
            random_trip, travel_time = random.choice(list(travel_times.items()))
            trip_count = hours_in_lectures // travel_time
            if trip_count > 0:
                return f"🌍 In your lecture hours, you could have driven from {random_trip} {num2words(trip_count).title()} times!"
            return f"🚗 You haven’t spent enough time in class to complete a drive from {random_trip} yet. Keep going!"

        if rand == 6:
            days_in_class = hours_in_lectures // 24
            if days_in_class < 1:
                return f"📚 You’ve spent {hours_in_lectures} hours in lectures."
            elif days_in_class < 30:
                return f"📚 You’ve spent {days_in_class} days attending lectures. Almost a month of learning!"
            return f"🗓️ You've spent a total of {days_in_class} days in class. That's dedication!"

        if rand == 7:
            trips_to_moon = hours_in_lectures // 69
            if trips_to_moon > 0:
                return f"🚀 You could have traveled to the moon {num2words(trips_to_moon).title()} times with your lecture hours!"
            return f"🌕 You’ve spent {hours_in_lectures} hours in class. Only {69 - hours_in_lectures} hours away from reaching the moon!"

        if rand == 8:
            launches = hours_in_lectures // 10
            if launches > 0:
                return f"🚀 You've spent enough time in lectures to power {launches} satellite launches to orbit. Astronomical dedication!"
            return "🌌 Your lecture hours are climbing, but not enough to launch a satellite yet. Keep attending – the stars are waiting!"
        if rand == 9:
            coffee_cups = int(hours_in_lectures // 0.25)
            if coffee_cups > 0:
                return f"☕ With your lecture hours, you could have brewed and enjoyed {coffee_cups} cups of coffee. That’s some serious caffeine-fueled learning!"
            return "🍵 You haven’t spent enough time in lectures to enjoy even a cup of coffee yet. Let’s get brewing with more attendance!"

    except Exception as e:
        return "🎉 You're doing great! Keep up the good work!"


def get_attendance_df(soup):
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


def generate_report(soup, prev):
    """Generates attendance summary."""
    name, roll_no, program, semester = get_user_details(soup)
    attendance_df_full, sap_id = get_attendance_df(soup)

    if prev and semester != "First":
        semester = list(SEMESTER_MAP.values())[
            list(SEMESTER_MAP.values()).index(semester) - 1
        ]

    try:
        # Filter attendance data by semester
        last_date = attendance_df_full["Date"].max()
        if semester in ["First", "Third", "Fifth", "Seventh", "Ninth", "Eleventh"]:
            start_date = datetime(last_date.year, 6, 1)
            end_date = datetime(last_date.year, 11, 30)
        else:
            if last_date.month == 12:
                start_date = datetime(last_date.year, 12, 1)
                end_date = datetime(last_date.year + 1, 5, 31)
            else:
                start_date = datetime(last_date.year - 1, 12, 1)
                end_date = datetime(last_date.year, 5, 31)

        attendance_df = attendance_df_full[
            (attendance_df_full["Date"] >= start_date)
            & (attendance_df_full["Date"] <= end_date)
        ].copy()

        out_data = []
        if not prev and (attendance_df["Date"].max() < last_date or attendance_df.empty):
            start_date = start_date.replace(year=start_date.year + 1)
            attendance_df = pd.DataFrame(columns=["Subject", "Date", "Present"])
            date_range = "N/A - N/A"
            funfact = "Uh-oh! Looks like you haven't attended any lectures this semester. Attend a few and check back."
        else:
            # Build attendance summary
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
            date_range = f"{attendance_df['Date'].min().strftime('%d.%m.%Y')} - {attendance_df['Date'].max().strftime('%d.%m.%Y')}"
            funfact = fun_fact(attendance_df.copy())

        # Build Attendance Heatmap data using full attendance data
        attendance_heatmap_data = (
            attendance_df_full.drop(columns=["Subject"])
            .assign(Date=pd.to_datetime(attendance_df_full["Date"]).dt.date)
            .groupby("Date", as_index=False)
            .agg(Present=("Present", "sum"))
            .loc[lambda df: df["Present"] != 0]
        )

        if attendance_heatmap_data.empty:
            attendance_heatmap_data = {}
        else:
            attendance_heatmap_data = {
                int(pd.Timestamp(date).timestamp() * 1000): int(count)
                for date, count in zip(
                    attendance_heatmap_data["Date"], attendance_heatmap_data["Present"]
                )
            }

        return {
            "Name": name,
            "SapID": sap_id,
            "RollNo": roll_no,
            "Program": program,
            "Semester": {
                "Name": semester,
                "Start": start_date.strftime("%m-%d-%Y"),
            },
            "Attendance": {
                "FunFact": funfact,
                "Range": date_range,
                "Data": out_data,
                "RawCSV": attendance_df.to_csv(index=False),
                "Heatmap": attendance_heatmap_data,
            },
        }
    except Exception as e:
        raise ValueError(f"(VE-6) Failed to generate attendance report: {e}") from e


def get_attendance(username, password, prev):
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
        if "MPSTME" not in college_name:
            raise ValueError(
                f"(VE-10) Unsupported College: {college_name}. This service is only available for MPSTME students."
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

    return generate_report(soup, prev)


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
        if request.args.get("p") == "true":
            data = get_attendance(username, password, True)
        else:
            data = get_attendance(username, password, False)
        log(request.headers.get("User-Agent"), start_time)
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
        return (
            jsonify(
                {
                    "error": f"(GE-1) An unexpected error occurred! Please try again later."
                }
            ),
            500,
        )
