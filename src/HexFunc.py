import datetime
import colorama

colorama.init(autoreset=True)

def debug(*msg):
    debug = True
    if debug:
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S.%f]")
        try:
            print("{} {}".format(colorama.Fore.GREEN + timestamp, " ".join(msg)))
        except:
            print("{} {} -> {}".format(colorama.Fore.RED + timestamp, colorama.Fore.WHITE, "ERROR", msg))
