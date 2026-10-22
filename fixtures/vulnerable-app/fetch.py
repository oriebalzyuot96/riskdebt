import requests, subprocess

requests.get("https://internal.example", verify=False)
subprocess.run("ls " + "x", shell=True)
