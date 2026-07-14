import sys

_CLI_COMMANDS = {"encrypt", "decrypt", "info", "genkey", "fingerprint"}

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in _CLI_COMMANDS:
        from obelisk.cli import main as cli_main
        cli_main()
    else:
        from obelisk.gui import main
        main()
