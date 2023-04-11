# How to run the project

1. Clone the repo
2. Optionally: create a new Python 3.10 virtual environment with `python -m virtualenv env`
    2a. Activate the virtual environment `source ./venv/Scripts/activate`
3. Install all the dependencies: `pip install -r requirements.txt`
4. Take a packet capture using `python capture.py`. It defaults to a 60s packet capture but you can adjust the time, network interface it is listening on and the database it stores the devices in using command line arguments. Use `python capture.py --help` to get them.
5. Analyse and represent that packet capture using `python analysis.py -p <your pcap name>` the pcap name is outputted by `capture.py` and defaults to a timestamp of when it was captured. Again, use `python analysis.py --help` to get help on the arguments.
