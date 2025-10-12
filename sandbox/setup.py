# 1) build your launcher first (no docker needed)
#    e.g., in project-bubble/sandbox:
#    gcc -O2 -Wall -Wextra -o seccomp_launcher seccomp_launcher.c -lseccomp

# 2) run the Flask frontend
cd project-bubble
python3 -m venv .venv && source .venv/bin/activate
pip install Flask==3.0.0
python orchestrator/app.py  # opens http://localhost:8090
