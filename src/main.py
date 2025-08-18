import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_cli():
    from app.cli.privana_cli import cli
    cli()

def run_gui():
    from app.gui.privana_gui import run_gui
    run_gui()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        run_gui()
    else:
        run_cli()