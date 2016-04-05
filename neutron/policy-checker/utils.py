class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def in_color(color, msg):
    return '{}{}{}'.format(color, msg, bcolors.ENDC)


def info_color(msg):
    return in_color(bcolors.OKBLUE, msg)


def ok_color(msg):
    return in_color(bcolors.OKGREEN, msg)


def warning_color(msg):
    return in_color(bcolors.WARNING, msg)


def fail_color(msg):
    return in_color(bcolors.FAIL, msg)


def print_with_color(color, msg):
    print(in_color(color, msg))


def print_green(msg):
    print_with_color(bcolors.OKGREEN, msg)


def print_warning(msg):
    print_with_color(bcolors.WARNING, msg)


def print_fail(msg):
    print_with_color(bcolors.FAIL, msg)


def print_info(msg):
    print_with_color(bcolors.OKBLUE, msg)
