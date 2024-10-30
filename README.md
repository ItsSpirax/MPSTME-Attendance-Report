# MPSTME Attendance Report

This repository contains the code for a web application that allows MPSTME students to easily check their attendance records. The application fetches attendance data from the SVKM portal and displays it in a user-friendly format.

**Note:** This project is for educational purposes only. Use it responsibly and at your own risk.

## Features

* Fetches attendance data from the SVKM portal.
* Displays attendance summary with subject-wise breakdown.
* Encrypts user credentials before sending them to the backend.
* Does not store user credentials or attendance data. Logs user agent and errors only for debugging purposes.
* Uses Cloudflare Turnstile for bot protection.
* Simple and easy-to-use interface.

## How it Works

1.  **Frontend:**
    *   The frontend is a simple HTML page with a form for user input (SAP ID and password).
    *   It uses JavaScript to handle user interaction and display the attendance data.
    *   Cloudflare Turnstile is used to prevent automated requests.

2.  **Backend:**
    *   The backend is a Flask application that handles the requests from the frontend.
    *   It uses the `requests` library to fetch data from the SVKM portal.
    *   User credentials are encrypted using RSA encryption before being sent to the portal.
    *   The `BeautifulSoup` library is used to parse the HTML content and extract the attendance data.
    *   The attendance data is then processed and returned to the frontend in JSON format.

## Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/ItsSpirax/MPSTME-Attendance-Report
    ```

2.  **Install the required packages:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up environment variables:**

    *   Create a `.env` file in the backend directory.
    *   Add your Cloudflare Turnstile Secret and Logging URL to the `.env` file:
    <br></br>
    ```
    TURNSTILE_SECRET = your_turnstile_secret
    LOGGING_URL = your_logging_url
    ```

4.  **Run the backend:**

    ```bash
    flask --app main.py run
    ```

5.  **Deploy the frontend:**

    *   The frontend can be deployed to any web server.
    *   The repository is hosted on Cloudflare Pages.

## Usage

1.  Go to the deployed frontend URL.
2.  Enter your SAP ID and portal password.
3.  Click on the "Get Attendance" button.
4.  Your attendance report will be displayed.

## Disclaimer

*   This project is not affiliated with SVKM or MPSTME in any way.
*   I am not responsible for any misuse of this application.
*   Use this application at your own risk.

## Contributing

Contributions are welcome! Feel free to open issues and pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
