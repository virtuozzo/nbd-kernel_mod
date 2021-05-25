#!/usr/bin/env python3

import os
import syslog
import sys
import time
from subprocess import Popen, PIPE


def logprint(msg, level=syslog.LOG_INFO, slog=False, ignorelevel=False):
    loglevel = syslog.LOG_INFO

    if ignorelevel or loglevel >= level:
        if slog:
            msg = '%s : %s' % ("NBD test:", str(msg))
            syslog.syslog(msg)
        else:
            logstr = '%s:%s' % ("NBD test:", time.strftime('%d-%m-%Y-%H:%M:%S ', time.gmtime())) + str(msg)
            print(logstr)

def systemExec(cmd, verbouse=False, shell=False):
    try:
        if verbouse:
            logprint("command %s" % str(cmd))

        process = Popen(cmd, shell=shell, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()
        if process.returncode != 0:
            if verbouse:
                logprint("o None e %s" % str(err, 'utf-8'))
            return None, str(err, 'utf-8')

        if verbouse:
            logprint("o %s e %s" % (str(out, 'utf-8'), str(err, 'utf-8')))

        return str(out, 'utf-8'), str(err, 'utf-8')
    except EnvironmentError as e:
        logprint("Failed to execute command %s exception: %s" % (str(cmd), str(e)))

    if verbouse:
        logprint("o None e None")

    return None, None

def insert_nbd():
    systemExec(["modprobe", "-rf", "nbd"])
    # insert kernel odule without parameters
    out, err = systemExec(["insmod", os.path.dirname(__file__)+"/nbd.ko"])
    if out is None:
        raise Exception("Can not insert nbd.ko " + str(err))

    found = False
    with open("/proc/modules") as modules:
        lines = modules.readlines() 
        for line in lines: 
            if line.startswith("nbd "):
                found = True
                break
    
    if not found:
        raise Exception("Failed to load nbd.ko not found in /proc/modules")


def insert_nbd_parameter_nbds_max():
    systemExec(["modprobe", "-rf", "nbd"])
    out, err = systemExec(["insmod", os.path.dirname(__file__)+"/nbd.ko", "nbds_max=0"])
    if out is not None:
        raise Exception("Can insert nbd.ko nbds_max=0 Negative case" + str(err))

    out, err = systemExec(["insmod", os.path.dirname(__file__)+"/nbd.ko", "nbds_max=300000"])
    if out is not None:
        raise Exception("Can insert nbd.ko nbds_max=300000 Negative case" + str(err))

    out, err = systemExec(["insmod", os.path.dirname(__file__)+"/nbd.ko", "nbds_max=1"])
    if out is None:
        raise Exception("Can not insert nbd.ko nbds_max=1" + str(err))

    out, err = systemExec(["ls -la /dev/nbd* | wc -l"], shell=True)
    if out.strip() != "1":
        raise Exception("count of NBD devices expected 1 actual " + str(out))

    systemExec(["modprobe", "-rf", "nbd"])
    out, err = systemExec(["insmod", os.path.dirname(__file__)+"/nbd.ko", "nbds_max=256"])
    if out is None:
        raise Exception("Can not insert nbd.ko nbds_max=256" + str(err))

    out, err = systemExec(["ls -la /dev/nbd* | wc -l"], shell=True)
    if out.strip() != "256":
        raise Exception("count of NBD devices expected 256 actual " + str(out))


def nbd_connection():
    # Make shure module loaded with 1 NBD
    systemExec(["modprobe", "-rf", "nbd"])
    systemExec(["insmod", os.path.dirname(__file__)+"/nbd.ko", "nbds_max=1"])
    # prepare fake device
    systemExec(["mknod", "/dev/fake-dev0", "b", "7", "200"], True)
    systemExec(["dd", "if=/dev/zero", "of=/tmp/dev0-backstore", "bs=512", "count=1000000"], True)
    systemExec(["losetup", "/dev/fake-dev0", "/tmp/dev0-backstore"], True)
    # Start server
    systemExec([os.path.dirname(__file__)+"/nbd-server", "9000", "/dev/fake-dev0"], True)
    # Connect with  client
    systemExec([os.path.dirname(__file__)+"/nbd-client", "127.0.0.1", "9000", "/dev/nbd0", "-b", "65535", "-U", "e82a5gsh164tdl", "-timeout", "60"], True)
    # Cleanup
    systemExec(["kill -9 `pgrep nbd-server`"], shell=True)
    systemExec(["losetup", "-d", "/dev/fake-dev0"])
    systemExec(["rm", "-rf", "/tmp/dev0-backstore"])


test_set={
    # Test name : test function
    "Insert": insert_nbd(),
    "Insert with parameter nbds_max": insert_nbd_parameter_nbds_max(),
    "Test nbd connection": nbd_connection(),
}

def main():
    logprint("Start nbd testing:")
    for test in test_set:
        logprint("Start %s test..." % test)
        try:
            test_set[test]
            sys.stdout.flush()
        except Exception as e:
            logprint("Test %s Failed. Reason %s" % (test, str(e)))
        
        logprint("Test %s Success" % test)


if __name__ == "__main__":
    main()
