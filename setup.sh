# 1) build your launcher first (no docker needed)
#    gcc -O2 -Wall -Wextra -o seccomp_launcher seccomp_launcher.c -lseccomp
cd sandbox
make clean && make
cd ..
# 2) run the Flask frontend
python3 -m venv .venv && source .venv/bin/activate
pip install Flask==3.0.0
pip install requests
python orchestrator/app.py  # opens http://localhost:8090