# Import
import base64
import difflib
from datetime import datetime
import json
import os
import re

from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
import requests
import pandas as pd

from flask import Flask, request, redirect, abort, jsonify, send_file
from flask_cors import CORS

import warnings

warnings.simplefilter(action="ignore", category=FutureWarning)


# Init
app = Flask(__name__)
CORS(app)


# Variables
LOGIN_URL = "https://portal.svkm.ac.in/usermgmt/login"
BRANCH_CHANGE_URL = "https://portal.svkm.ac.in/usermgmt/"
HOMEPAGE_URL = "https://portal.svkm.ac.in/MPSTME-NM-M/homepage"
ATTENDANCE_URL = "https://portal.svkm.ac.in/MPSTME-NM-M/viewDailyAttendanceByStudent"

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


# Functions
def cf_turnstile_verify(response, remoteip):
    return json.loads(
        requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": os.environ["TURNSTILE_API_KEY"],
                "response": response,
                "remoteip": remoteip,
            },
        ).content
    )["success"]


def encrypt_message(message):
    encoded = message.encode("utf-8")

    ciphertext = PUBLIC_KEY.encrypt(
        encoded,
        crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(ciphertext).decode("utf-8")


def get_user_details(soup):
    user_details = soup.find_all("div", class_="form-group")

    name = user_details[0].text.split(":")[1].strip().title()
    roll_no = user_details[3].text.split(":")[1].strip()
    program = user_details[1].text.split(":")[1].split("-")[0].strip().title()
    semester = SEMESTER_MAP[user_details[2].text.split(":")[1].strip().split()[1]]
    return name, roll_no, program, semester


def get_attendance_df(soup, semester):
    attendance_list = soup.find("div", class_="studAttList").find("tbody").find_all("tr")
    sapid = attendance_list[0].find_all("td")[1].text

    attendance_df = pd.DataFrame(columns=["Subject", "Date", "Present"])

    for row in attendance_list:
        data = row.find_all("td")

        subject = re.split(r"P\d|U\d|T\d", data[2].text)[0].strip()
        date = datetime.strptime(data[5].text + data[6].text.split("-")[0][:-3], "%d-%m-%Y%H.%M")
        present = data[7].text == "P"
        time = data[6].text.split("-")[0]

        attendance_df = pd.concat([attendance_df, pd.DataFrame([[subject, date, present]], columns=["Subject", "Date", "Present"])], ignore_index=True)

    last_date = attendance_df["Date"].max()

    if semester in ["First", "Third", "Fifth", "Seventh", "Ninth", "Eleventh"]:
        attendance_df = attendance_df[(attendance_df["Date"] >= datetime(last_date.year, 6, 15)) & (attendance_df["Date"] <= datetime(last_date.year, 12, 31))]
    else:
        attendance_df = attendance_df[(attendance_df["Date"] >= datetime(last_date.year, 1, 1)) & (attendance_df["Date"] <= datetime(last_date.year, 6, 14))]

    subjects = []
    for sub in attendance_df["Subject"].unique():
        for s in subjects:
            if difflib.SequenceMatcher(None, sub, s).ratio() > 0.75:
                attendance_df["Subject"] = attendance_df["Subject"].replace(sub, s)
                break
        else:
            subjects.append(sub)

    attendance_df["Subject"] = attendance_df["Subject"].apply(lambda x: difflib.get_close_matches(x, subjects, n=1, cutoff=0.57)[0] if difflib.get_close_matches(x, subjects, n=1, cutoff=0.75) else x)

    attendance_df = attendance_df.sort_values(by="Date")
    return attendance_df, sapid


def parse_attendance_df(response_text):
    soup = BeautifulSoup(response_text, "html.parser")

    name, roll_no, program, semester = get_user_details(soup)
    attendance_df, sap_id = get_attendance_df(soup, semester)

    out_data = []
    for subject in attendance_df["Subject"].unique():
        present_count = attendance_df[attendance_df["Subject"] == subject]["Present"].sum()
        total_count = attendance_df[attendance_df["Subject"] == subject].shape[0]
        percentage = round((present_count / total_count) * 100, 2)
        out_data.append(
            {
                "Subject": subject,
                "Present": present_count,
                "Total": total_count,
                "Percentage": percentage,
            }
        )

    return {
        "Name": name,
        "SapID": sap_id,
        "RollNo": roll_no,
        "Program": program,
        "Semester": semester,
        "Attendance": {
            "Range": f"{attendance_df['Date'].min().strftime('%d.%m.%Y')} - {attendance_df['Date'].max().strftime('%d.%m.%Y')}",
            "Data": out_data,
        },
    }


def get_attendance(username, password):
    with requests.Session() as s:
        try:
            r = s.post(
                LOGIN_URL,
                data={
                    "jspname": "nm",
                    "username": encrypt_message(username),
                    "password": encrypt_message(password),
                },
                timeout=25,
            )
        except requests.exceptions.Timeout:
            raise Exception("The SVKM portal is taking too long to respond. It might be down. Please try again after sometime.")
        except requests.exceptions.ConnectionError:
            raise Exception("Unable to connect to the SVKM portal. Please try again after sometime.")
        if r.status_code != 200:
            raise Exception("The SVKM portal seems to be down. Please try again later.")
        if r.url == LOGIN_URL:
            raise Exception("Incorrect username or password. Please double-check and try again.")

        if r.url == BRANCH_CHANGE_URL:
            branchOptions = BeautifulSoup(r.text, "html.parser").select("option")[1:]
            for option in branchOptions:
                option = option["value"]

                if option.split("-")[-1] != username[0:4]:
                    selectedBranch = option
                    break

            try:
                r = s.post(
                    BRANCH_CHANGE_URL,
                    data={"appName": selectedBranch},
                )
            except Exception as e:
                raise Exception(f"Error changing branch: {e}")

            if r.status_code != 200:
                raise Exception("The SVKM portal seems to be down. Please try again later.")

        if r.url != HOMEPAGE_URL:
            raise Exception("An unexpected error occurred. Please report this issue to administrator@spirax.me")

        response = s.get(ATTENDANCE_URL)
        return parse_attendance_df(response.text)


# Web Request Routes
@app.route("/", methods=["GET"])
def home():
    return redirect("https://attendance.spirax.me/", code=301)


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return send_file("media/favicon.ico")


@app.route("/v1/getAttendanceReport", methods=["POST"])
def attendance():
    if cf_turnstile_verify(request.json["cf-turnstile-response"], request.headers.get("Cf-Connecting-Ip")):
        username = request.json["username"].strip()
        if not username.isdigit():
            return jsonify({"error": "Invalid username. Please enter your SAP ID."}), 400
        password = request.json["password"].strip()
        if not 8 <= len(password) <= 20:
            return jsonify({"error": "Invalid password. Please enter a valid password."}), 400
        try:
            attendance = get_attendance(username, password)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"message": "200: Success", "data": attendance})
    else:
        abort(403)
