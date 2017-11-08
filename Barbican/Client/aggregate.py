import linecache
import sys

def get_value(line):
    return line.split(":")[1].split()[0]

def main(users):
    rps = 0.0
    tpr = 0.0
    for x in range(1, users + 1):
        rps_line = linecache.getline("user_" + str(x) + ".log", 24)
        rps = rps + float(get_value(rps_line))
        tpr_line = linecache.getline("user_" + str(x) + ".log", 25)
        tpr = tpr + float(get_value(tpr_line))

    print "Requests per second : " + str(rps/users)
    print "Time per request    : " + str(tpr/users)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Invalid Command!"
        print "Usage : python aggregate <users>"
    else:
        main(int(sys.argv[1]))
