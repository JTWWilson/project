import pyshark
from datetime import datetime

def capture(output_file=None):
    # Default name for file is the date and time of its capture
    if output_file is None:
        now = datetime.now()
        output_file = "{}-{}-{}_{}-{}-{}.pcap".format(now.year, now.month, now.day, now.hour, now.minute, now.second)
    cap = pyshark.LiveCapture(output_file=output_file, interface="WiFi")
    cap.sniff(timeout=60)

if __name__ == "__main__":
    capture()
