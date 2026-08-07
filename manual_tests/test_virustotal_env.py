import os

from dotenv import load_dotenv


load_dotenv()


api_key = os.getenv(
    "VIRUSTOTAL_API_KEY"
)


if api_key:

    print(
        "VirusTotal API key loaded successfully."
    )

else:

    print(
        "ERROR: VirusTotal API key not found."
    )