#!/usr/bin/env python


"""
Server Density plugin for monitoring occurrences of "triggers" in
log files.  It counts the number of "triggers" since the last run.
Thresholds are used to limit the checks performed.

For example, this shows a check once MODIFICATION_TIME_THRESHOLD seconds have
passed, where no triggers are found in the log:

    $ python LogTriggers.py 
    curr_mtime - prev_mtime > MODIFICATION_TIME_THRESHOLD
    1298615102.58 - 1298611543.64 > 60 == True
    1298615102.58 - 1298611543.64 = 3558.93702388
    curr_len - prev_len > MODIFICATION_BYTES_THRESHOLD
    0 - 1966787 > 1000 == False
    0 - 1966787 = -1966787
    {'memcached_down': 0, 'internal_server_error': 0, 'elasticsearch_servers_unavailable': 0, 'job_error': 0}

For example, this shows a check where no thresholds have passed so no checks
are performed on the log:

    $ python LogTriggers.py 
    curr_mtime - prev_mtime > MODIFICATION_TIME_THRESHOLD
    1298615102.58 - 1298615882.39 > 60 == False
    1298615102.58 - 1298615882.39 = -779.814103603
    curr_len - prev_len > MODIFICATION_BYTES_THRESHOLD
    0 - 0 > 1000 == False
    0 - 0 = 0
    {}
"""


import os
import sys
import re
from shutil import copyfile
from stat import ST_SIZE


TMP_WORK_DIR = "/tmp"

# Maps log files to triggers.  Each trigger consists of a summary name and a
# compiled regular expression.
LOG_TRIGGER_MAP = {
    "/this/is/an/example.log" : {
            # Example regular expressions
            "i_am_an_example" : re.compile("server [^ ]+ is dying"),
            "i_am_also_an_example" : re.compile("server [^ ]+ is dead"),
            "i_am_yet_another_example" : re.compile("server [^ ]+ is [fF][uU][bB][aA][rR]"),
        },
    "/this/is/another/example_of_a.log" : {
            # Example regular expressions
            "this_is_an_example" : re.compile("server [^ ]+ is doing great"),
            "this_is_also_an_example" : re.compile("server [^ ]+ is doing awesome"),
            "this_is_yet_another_example" : re.compile("server [^ ]+ is sentient"),
        },
}

# Default threshold for the modification time (in seconds).  If the log
# file has been updated MODIFICATION_TIME_THRESHOLD seconds (or greater)
# since the last check, we check again.  This allows for rate limiting
# the checks.  Defaults to 60 seconds - other values only really useful
# if they're taking longer than 1 minute or the log file is updated very
# infrequently.
MODIFICATION_TIME_THRESHOLD = 60

# Default threshold for the size of modification (in bytes).  If the log
# file has MODIFICATION_BYTES_THRESHOLD bytes (or greater) since the last
# check, we check again.  This allows for rate limiting the checks.  Defaults
# to 1000 bytes.
MODIFICATION_BYTES_THRESHOLD = 1000


class LogTriggers:
    def __init__(self, agent_config, checks_logger, raw_config):
        # Standard agent guff
        self.agent_config = agent_config
        self.checks_logger = checks_logger
        self.raw_config = raw_config
        # If the working directory doesn't exist we attempt to create it
        if not os.path.isdir(TMP_WORK_DIR):
            self.checks_logger.debug("No work directory, creating %s" % TMP_WORK_DIR)
            os.makedirs(TMP_WORK_DIR)

    def run(self):
        stats = {}

        for log_file, triggers in LOG_TRIGGER_MAP.items():
            # No log file, no work to do
            if not os.path.isfile(log_file):
                self.checks_logger.warn("No such file: %s" % log_file)
                continue
            self.checks_logger.debug("Checking %s" % log_file)

            # Initialise the stats counts
            for trigger_name in triggers.keys():
                stats[trigger_name] = 0

            # Make sure we've primed every log file
            log_file_name = os.path.basename(log_file)
            prev_log_file = os.path.join(TMP_WORK_DIR, log_file_name)
            if not os.path.isfile(prev_log_file):
                self.checks_logger.debug("Priming %s with %s" % (prev_log_file, log_file))
                copyfile(log_file, prev_log_file)
                continue

            # Grab the modified time of the previous log file and
            # current log file
            prev_mtime = os.path.getmtime(prev_log_file)
            curr_mtime = os.path.getmtime(log_file)
            self.checks_logger.debug("curr_mtime - prev_mtime > MODIFICATION_TIME_THRESHOLD")
            self.checks_logger.debug("%s - %s > %s == %s" % (curr_mtime, prev_mtime, MODIFICATION_TIME_THRESHOLD, (curr_mtime - prev_mtime) > MODIFICATION_TIME_THRESHOLD))
            self.checks_logger.debug("%s - %s = %s" % (curr_mtime, prev_mtime, (curr_mtime - prev_mtime)))

            # Grab the length of the previous log file and current
            # log file
            prev_len = os.stat(prev_log_file)[ST_SIZE]
            curr_len = os.stat(log_file)[ST_SIZE]
            self.checks_logger.debug("curr_len - prev_len > MODIFICATION_BYTES_THRESHOLD")
            self.checks_logger.debug("%s - %s > %s == %s" % (curr_len, prev_len, MODIFICATION_BYTES_THRESHOLD, (curr_len - prev_len) > MODIFICATION_BYTES_THRESHOLD))
            self.checks_logger.debug("%s - %s = %s" % (curr_len, prev_len, (curr_len - prev_len)))

            # If the current log file has modifications more than
            # MODIFICATION_TIME_THRESHOLD seconds old or
            # MODIFICATION_BYTES_THRESHOLD bytes in size, let's check
            # the new entries
            if ((curr_mtime - prev_mtime) >= MODIFICATION_TIME_THRESHOLD) or \
               ((curr_len - prev_len) >= MODIFICATION_BYTES_THRESHOLD):
                # Update the stats with counts of each trigger,
                # then update the previous log file
                stats.update(self.count_triggers_since_pos(log_file, prev_len, triggers))
                self.checks_logger.debug("count_triggers_since_pos(\"%s\", %d, %s)" % (log_file, prev_len, triggers))
                copyfile(log_file, prev_log_file)
                self.checks_logger.debug("copyfile(\"%s\", \"%s\")" % (log_file, prev_log_file))
            else:
                self.checks_logger.debug("nothing to do")

        return stats

    def count_triggers_since_pos(self, log_file, start_pos, triggers):
        triggers_count = {}
        f = open(log_file, "r")
        f.seek(start_pos)
        data = f.read()
        for name, trigger_re in triggers.items():
            triggers_count[name] = len(trigger_re.findall(data))
        return triggers_count


if __name__ == "__main__":
    from pprint import pprint
    import logging
    logger = logging.getLogger("LogTriggers")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    ltm = LogTriggers(None, logger, None)
    pprint(ltm.run())
