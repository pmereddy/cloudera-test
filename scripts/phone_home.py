# (c) Copyright 2010-2014 Cloudera, Inc.

"""This module can be used in one of two ways. It can be run independently from
the command line, given a user, host, port, dropdir, and file, it will transfer
the file to the host's dropdir. This is meant to phone cluster statistics to
conductor for collection.

This script can also automatically be used by cluster statistics, where its
transfer_file function is invoked to transfer the file to home."""

import os
import sys
import subprocess
import tempfile
import optparse
import logging
import socket

# Attempt to use new version of md5 to avoid nasty warnings
try:
    from hashlib import md5
except ImportError:
    import md5


logger = logging.getLogger()
COPS_PUBLIC_KEY="cops.mtv.cloudera.com,172.20.45.27 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA2A4SRMUf08kv82jGQmIaDO8obPbkUOcaxql51kzMFRWWEGOVibQJt6rnuHlzqnujxvyPmI9F/VZKWNg+Bljm9XKxQ6PrjYgG7Mcm3pO+ae+c28nn3Qg4somCzVLnMBS4HkkmTOiX5Bct4R7zKHElsKSY8PMPGQOyfnCjnZwi/w4E1sYYqrLR1TjYrwFnIJUR9X6HEjqEEVK0dT9uARAhQYdUL3ykRPlyM+aHt8KSssfgltNNDdLcM3yTrW58B8yysCzO5MGT7LR8yuaCDOVwPhQxa5QbCdUgYJq2mbQXpdwkyyHtrMDGorykB+oG6GLr093oCqJrAinlUNgL4eP6yQ==\ncops.cloudera.com,173.227.38.190 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA2A4SRMUf08kv82jGQmIaDO8obPbkUOcaxql51kzMFRWWEGOVibQJt6rnuHlzqnujxvyPmI9F/VZKWNg+Bljm9XKxQ6PrjYgG7Mcm3pO+ae+c28nn3Qg4somCzVLnMBS4HkkmTOiX5Bct4R7zKHElsKSY8PMPGQOyfnCjnZwi/w4E1sYYqrLR1TjYrwFnIJUR9X6HEjqEEVK0dT9uARAhQYdUL3ykRPlyM+aHt8KSssfgltNNDdLcM3yTrW58B8yysCzO5MGT7LR8yuaCDOVwPhQxa5QbCdUgYJq2mbQXpdwkyyHtrMDGorykB+oG6GLr093oCqJrAinlUNgL4eP6yQ=="

def generate_hash(file_name):
    """Given a file_name, this will open the file, read the contents, and
    generate an md5 hash of the file."""
    # If we're using hashlib module, the new() method doesn't exist so we will
    # catch an attribute error and create the object properly
    try:
        m = md5.new()
    except AttributeError:
        m = md5()

    f = open(file_name, "rb")
    try:
        while True:
            data = f.read(128)
            if not data:
                break
            m.update(data)
    finally:
        f.close()
    return m.hexdigest()

def store_cops_public_key():
    """Stores the cops.cloudera.com public key to a temp file to be passed
    to the UserKnownHostsFile option of SFTP command
    :return: temp file where the public key is stored
    """
    fd, cops_public_key_path = tempfile.mkstemp()
    logger.info("Storing cops.cloudera.com public key to %s", cops_public_key_path)
    os.write(fd, COPS_PUBLIC_KEY)
    os.close(fd)
    return cops_public_key_path


def get_transfer_command(port, user, host, file_name, drop_dir, key_path, sftp=False):
    """Gets an appropriate sftp or curl command to upload the given file to the given location.
    Parameters:
      - port - the port of the upload server.
      - user - the user to upload as.
      - file_name - resolvable path to file to upload.
      - drop_dir - the location on the upload server for the file. For HTTPS uploads, only the 
                   filename is retained.
      - sftp - indicates whether to upload with https (curl) [enabled by default] or sftp """
    if not sftp:
        # use https
        transfer_file_command = "curl -u \"%s:cm_diag@\" --header \"X-FILENAME: %s\" --data-binary '@%s' https://%s:%s/upload"
        return transfer_file_command % (user, os.path.basename(drop_dir), file_name, host, port)
    else:
        transfer_file_command = "sftp -b /dev/stdin -o Port=%s -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes %s@%s <<EOF\nprogress\nput %s %s\nEOF"
        return transfer_file_command % (port, key_path, user, host, file_name, drop_dir)
        

def transfer_file(user, host, port, drop_dir, file_name, sftp=False):
    """Given a user, host, port, drop directory, and filename, transfer the
    file to the host, and place it in its drop directory. This is done over
    SFTP or HTTPS depending on the sftp parameter. Return True on success,
    False otherwise."""
    dest_file = os.path.join(drop_dir, os.path.basename(file_name))
    key_path = None
    if sftp:
        key_path = store_cops_public_key()
    transfer_tarball_command = get_transfer_command(port, user, host, file_name, dest_file, key_path, sftp)

    try:
        logger.info("Running command %s" % (transfer_tarball_command))
        ret_code = subprocess.call(transfer_tarball_command, shell=True)

        if ret_code != 0:
            logger.error("Error transferring file %s. Exited with return code %s" % (file_name, ret_code))
            return False
        else:
            logger.info("Successfully transferred file %s" % (file_name))
            logger.info("Sending commit")
            commitfile_path = tempfile.mktemp()
            commitfile_handle = open(commitfile_path, "w")
            try:
                md5hash = generate_hash(file_name)
                commitfile_handle.write(md5hash)
            finally:
                commitfile_handle.close()
            try:
                dest_file = os.path.join(drop_dir, os.path.basename(file_name) + ".commit")
                transfer_commit_command = get_transfer_command(port, user, host, commitfile_path, dest_file, key_path, sftp)
                logger.info("Running command %s" % (transfer_commit_command))
                ret_code = subprocess.call(transfer_commit_command, shell=True)
                if ret_code != 0:
                    logger.error("Error transferring file %s. Exited with return code %s" % (commitfile_path, ret_code))
                    return False
            finally:
                os.remove(commitfile_path)
            return True
    finally:
        if key_path is not None:
            os.remove(key_path)


def handle_args():
    """Handle command line arguments, returning the options."""
    usage = "phone_home.py --user=USER --host=HOST --port=PORT --dropdir=DIR [--sftp] --file=FILE"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-u", "--user", help="Username for connection")
    parser.add_option("-a", "--host", help="Hostname for connection", default="cops.cloudera.com")
    parser.add_option("-p", "--port", help="Port to connect on", type="int")
    parser.add_option("-d", "--dropdir", help="Drop directory On Cloudera's server", default="drop")
    parser.add_option("-f", "--file", help="File to upload to Cloudera support")
    parser.add_option("-s", "--sftp", help="Upload using SFTP instead of curl over HTTPS which is the default", action="store_true")
    (options, _) = parser.parse_args()

    # If running Cloudera's network, force some options
    # Otherwise use the settings from the commandline
    try:
        socket.gethostbyname('cops.mtv.cloudera.com')
        options.sftp = True
        options.host = 'cops.mtv.cloudera.com'
        sys.stderr.write("Redirecting the copy to %s using scp\n" % options.host)
    except:
        pass

    # Handle Required Options
    # - Set the default port which is different for sftp
    if not options.port:
        if options.sftp:
            options.port = "22"
        else:
            options.port = "1011"

    # - Set the default user which is different for sftp
    if not options.user:
        if options.sftp:
            options.user = "anonymous"
        else:
            options.user = "cops"


    # - If no file was provided, but a single argument was provided...assume it's the filename
    if not options.file and len(sys.argv) == 2:
        options.file = sys.argv[1]
    # - Do the same thing if there are two arguments and the first is -s/--sftp
    if not options.file and len(sys.argv) == 3 and (sys.argv[1] == "-s" or sys.argv[1] == "--sftp"):
        options.file = sys.argv[2]

    # - Check if an upload file was provided
    if not options.file:
        sys.stderr.write("No file provided to upload, use --file <filename>\n")
        sys.exit(1)

    # - Handle non-readable / non-existent files
    if not can_upload_file(options.file):
        sys.stderr.write("Unable to read file, please make sure it exists and is readable\n")
        sys.exit(1)

    # Parse slashes out of the filename
    options.file = options.file.replace("\\", "")

    return options


def main():
    """Invoked as a main from the command line, so parse the command line arguments,
    and attempt to transfer the file."""
    options = handle_args()

    if options.sftp:
        if not has_program("sftp"):
            sys.stderr.write("sftp is not installed, please install it before continuing\n")
            sys.exit(1)
    else:
        if not has_program("curl"):
            sys.stderr.write("curl is not installed, please install it before continuing\n")
            sys.exit(1)

    success = transfer_file(options.user, options.host, options.port,
                            options.dropdir, options.file, options.sftp)
    if not success:
        sys.exit(1)


def init_logger():
    """Initialize some default logging settings"""
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(module)-25s %(levelname)-8s: %(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)


def can_upload_file(fpath):
    """Does this file exist and is it readable?"""
    return os.path.isfile(fpath) and os.access(fpath, os.R_OK)


def has_program(name):
    """Does this system have the given program on it?"""
    for path in os.environ["PATH"].split(os.pathsep):
        path = path.strip('"')
        fpath = os.path.join(path, name)
        if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
            return True

    return False


if __name__ == "__main__":
    print("Cloudera Support Upload Tool")
    init_logger()
    main()
