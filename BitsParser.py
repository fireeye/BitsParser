# Copyright 2021 FireEye, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on 
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the 
# specific language governing permissions and limitations under the License.


import os
import sys
import json
import string
import struct
import hashlib
import argparse
import datetime
import traceback

from ese.ese import ESENT_DB

# On Windows advapi32 will be used to resolve SIDs
try:
    import advapi32
except Exception:
    pass

import bits
from bits.structs import FILE, CONTROL, JOB


# XFER_HEADER defined as bytes
XFER_HEADER = b'\x36\xDA\x56\x77\x6F\x51\x5A\x43\xAC\xAC\x44\xA2\x48\xFF\xF3\x4D'


# File and job delimiter constants for Windows 10
WIN10_FILE_DELIMITER = b'\xE4\xCF\x9E\x51\x46\xD9\x97\x43\xB7\x3E\x26\x85\x13\x05\x1A\xB2'
WIN10_JOB_DELIMITERS = [
    b'\xA1\x56\x09\xE1\x43\xAF\xC9\x42\x92\xE6\x6F\x98\x56\xEB\xA7\xF6',
    b'\x9F\x95\xD4\x4C\x64\x70\xF2\x4B\x84\xD7\x47\x6A\x7E\x62\x69\x9F',
    b'\xF1\x19\x26\xA9\x32\x03\xBF\x4C\x94\x27\x89\x88\x18\x95\x88\x31',
    b'\xC1\x33\xBC\xDD\xFB\x5A\xAF\x4D\xB8\xA1\x22\x68\xB3\x9D\x01\xAD',
    b'\xd0\x57\x56\x8f\x2c\x01\x3e\x4e\xad\x2c\xf4\xa5\xd7\x65\x6f\xaf',
    b'\x50\x67\x41\x94\x57\x03\x1d\x46\xa4\xcc\x5d\xd9\x99\x07\x06\xe4'
]


class BitsParser:

    def __init__(self, queue_dir, carve_db, carve_all, out_file):

        self.queue_dir = queue_dir
        self.carve_db_files = carve_db
        self.carve_all_files = carve_all
        self.out_file = out_file

        self.sid_user_cache = {}
        self.visited_jobs = set()
        # Assume files are from Windows 10 by default -- will be verified later
        self.is_win_10 = True


    def get_username_from_sid(self, sid):
        """ Returns the username associated with the given SID by calling LookupAccountSid """

        # Cache usernames to improve efficiency with repeated lookups
        if sid in self.sid_user_cache:
            return self.sid_user_cache[sid]
        try:
            name, domain, _ = advapi32.LookupAccountSid(advapi32.ConvertStringSidToSid(sid))
            username = domain+"\\"+name
            self.sid_user_cache[sid] = username
            return username
        except Exception as e:
            print(f'Failed to resolve sid {sid}: ' + str(e), file=sys.stderr)
            self.sid_user_cache[sid] = None
            return None


    def is_qmgr_database(file_data):
        """ Attempts to locate pattern at 0x10 found in qmgr databases (prior to Windows 10) """
        if file_data[0x10:0x20] == b'\x13\xf7\x2b\xc8\x40\x99\x12\x4a\x9f\x1a\x3a\xae\xbd\x89\x4e\xea':
            return True
        return False


    def is_qmgr10_database(file_data):
        """ Attempts to locate ESE database magic number found in Windows 10 qmgr databases """
        if file_data[4:8] == b'\xEF\xCD\xAB\x89':
            return True
        return False


    def load_qmgr_jobs(self, file_data):
        """ Processes the given qmgr database file with ANSSI-FR, parses jobs (possibly carves jobs), and returns a list of discovered jobs. """

        jobs = []
        analyzer = bits.Bits.load_file(file_data)
        if self.carve_db_files or self.carve_all_files:
            for job in analyzer:
                jobs.append(BitsJob(job, self))
        else:
            for job in analyzer.parse():
                jobs.append(BitsJob(job, self))
        return jobs


    def load_non_qmgr_jobs(self, file_data):
        """ Attempts to "carve" jobs from non-qmgr files (sometimes job remnants can be found in other files) """

        jobs = []
        analyzer = bits.Bits()
        # Search for the XFER header and get 2KB of data around it
        for sample in bits.sample_disk(file_data, XFER_HEADER, 2048):
            analyzer.append_data(sample)
        # Attempt to parse jobs from memory block
        analyzer.guess_info()
        for job in analyzer:
            jobs.append(BitsJob(job, self))
        return jobs


    def parse_qmgr10_job(self, job_data):
        """Attempt to parse job data from the Win10 qmgr database"""
        # Skip small entires that are not valid
        if len(job_data) < 128:
            return None
        try:

            # Because it can be expensive to parse a JOB structure if the data is not valid,
            # do a simple check to see if the job name length is valid
            name_length = struct.unpack_from("<L", job_data, 32)[0]
            if 32 + name_length * 2 > len(job_data):
                return None

            # Parse as a JOB
            try:
                parsed_job = JOB.parse(job_data)
            except Exception:
                # If it fails to parse as a JOB, at least try to parse as a CONTROL struct
                try:
                    parsed_job = CONTROL.parse(job_data)
                except Exception:
                    return None

            try:
                # Following the JOB entry, there are usually XFER refs to FILE GUIDs
                parsed_job['files'] = []
                xfer_parts = job_data.split(XFER_HEADER)
                file_ref_data = xfer_parts[1]
                num_file_refs = struct.unpack_from("<L", file_ref_data)[0]
                # Validate the number of file references to avoid expensive parsing failures
                if 4 + num_file_refs * 16 > len(file_ref_data):
                    return None
                for i in range(0, num_file_refs):
                    # Parse the GUID and attempt to find correlated FILE
                    cur_guid = file_ref_data[4+i*16:4+(i+1)*16]
                    file_job = self.file_entries.pop(cur_guid, None)
                    if file_job:
                        parsed_job['files'].extend(file_job['files'])
            except Exception:
                pass

            # Build a BitsJob for the job entry
            new_job = BitsJob(parsed_job, self)
            return new_job
        except Exception:
            print(f'Exception occurred parsing job: ' + traceback.format_exc(), file=sys.stderr)
            return None


    def parse_qmgr10_file(self, file_data, suppress_duplicates):
        """Attempt to parse file data from the Win10 qmgr database"""

        # Skip small entires that are not valid
        if len(file_data) < 256:
            return None
        try:
            # Because it can be expensive to parse a FILE structure if the data is not valid,
            # do a simple check to see if the filename length is valid
            filename_length = struct.unpack_from("<L", file_data)[0]
            if 4 + filename_length * 2 > len(file_data):
                return None

            # Parse the FILE
            parsed_file = FILE.parse(file_data)

            # Build a BitsJob for the file entry (set entry as files list)
            cur_job = {}
            cur_job['files'] = [parsed_file]

            # There is usually a timestamp 29 bytes into the file structure, which appears to correlate to creation time
            filetime = struct.unpack_from("<Q", file_data, parsed_file.offset + 29)[0]
            if filetime != 0:
                cur_job['ctime'] = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=(filetime / 10))

            return cur_job
        except Exception:
            return None


    @staticmethod
    def process_qmgr10_rows(table):
        """Given a table, processes the rows by getting data and excluding leading GUIDs"""

        # Enumerate records
        for i in range(table.get_number_of_records()):
            cur_record = table.get_record(i)
            num_values = cur_record.get_number_of_values()
            if num_values != 2:
                continue
            try:
                # Get the record Id GUID
                if cur_record.is_long_value(0):
                    guid = cur_record.get_value_data_as_long_value(0).data
                else:
                    guid = cur_record.get_value_data(0)

                # Get the record Blob data
                if cur_record.is_long_value(1):
                    val = cur_record.get_value_data_as_long_value(1).data
                else:
                    val = cur_record.get_value_data(1)

                # Return the data if it's at least 16 bytes (exclude the first 16 bytes)
                if len(val) > 16:
                    yield guid, val[16:]
            except Exception:
                pass


    def load_qmgr10_db(self, file_data):
        """Loads the qmgr.db and attempts to enumerate the Jobs and Files tables to parse records"""
        jobs = []
        self.file_entries = {}

        # Parse the database
        ese = ESENT_DB(file_data)

        # Enumerate files, store file entries to file_entries mapping
        files_table = ese.openTable("Files")
        while True:
            file_record = ese.getNextRow(files_table)
            if file_record is None:
                break
            guid = file_record.get(b'Id')
            new_job = self.parse_qmgr10_file(file_record.get(b'Blob', b''), False)
            if guid and new_job:
                self.file_entries[guid] = new_job

        # Enumerate jobs (and correlate to files)
        jobs_table = ese.openTable("Jobs")
        while True:
            job_record = ese.getNextRow(jobs_table)
            if job_record is None:
                break
            guid = job_record.get(b'Id')
            job_data = job_record.get(b'Blob', b'')[16:]
            new_job = self.parse_qmgr10_job(job_data)
            if guid and new_job:
                jobs.append(new_job)

        # If any file records were not correlated to JOBs just add them as their own jobs
        for guid, file_job in self.file_entries.items():
            jobs.append(BitsJob(file_job, self))

        return jobs


    def carve_qmgr10_records(self, file_data):
        """ Attempts to carve jobs from a qmgr database file using expected file and job GUIDs"""
        jobs = []
        self.file_entries = {}

        # Carve file entries from the database, store to file_entries mapping
        cur_offset = file_data.find(WIN10_FILE_DELIMITER)
        while cur_offset > 0:
            next_offset = file_data.find(WIN10_FILE_DELIMITER, cur_offset+len(WIN10_FILE_DELIMITER))
            if next_offset > 0:
                file_job = self.parse_qmgr10_file(file_data[cur_offset+16:next_offset], True)
            else:
                file_job = self.parse_qmgr10_file(file_data[cur_offset+16:], True)
            if file_job:
                guid = file_data[cur_offset-22:cur_offset-6]
                self.file_entries[guid] = file_job
            cur_offset = next_offset

        # Carve jobs from the database (note that there are multiple potential job delimiters)
        for job_delimiter in WIN10_JOB_DELIMITERS:
            carved_jobs = file_data.split(job_delimiter)
            if len(carved_jobs) == 1:
                continue
            for i in range(1, len(carved_jobs)):
                new_job = self.parse_qmgr10_job(carved_jobs[i])
                if new_job:
                    new_job.job_dict['Carved'] = True
                    jobs.append(new_job)

        # If any file records were not correlated to JOBs just add them as their own jobs
        for guid, carved_job in self.file_entries.items():
            file_job = BitsJob(carved_job, self)
            file_job.job_dict['Carved'] = True
            jobs.append(file_job)

        return jobs


    def load_qmgr10_jobs(self, file_data):
        """
        Attempt to parse Windows 10 qmgr jobs by carving JOB and FILE records out of the database using record identifiers.
        Unfortunately there is not a way to correlate job and file entries in Win10 qmgr databases, so we have to create separate entries for each.
        """

        # Parse active job and file records in the database
        jobs = self.load_qmgr10_db(file_data)

        # Carve deleted job and file entires if requested
        if self.carve_db_files or self.carve_all_files:
            jobs.extend(self.carve_qmgr10_records(file_data))

        return jobs


    def output_jobs(self, file_path, jobs):
        """Cleans up and outputs the parsed jobs from the qmgr database files"""

        # If an output file is specified, open it and use it instead of stdout
        if self.out_file:
            orig_stdout = sys.stdout
            sys.stdout = open(self.out_file, "w")

        try:
            for job in jobs:
                # Skip incomplete carved jobs as they do not contain useful info
                if job.is_carved() and not job.is_useful_for_analysis():
                    continue

                # Output unique jobs
                if job.hash not in self.visited_jobs:
                    formatted_job = json.dumps(job.job_dict, indent=4)
                    print(formatted_job)

                    self.visited_jobs.add(job.hash)
        finally:
            if self.out_file:
                sys.stdout.close()
                sys.stdout = orig_stdout


    def process_file(self, file_path):
        """ Processes the given BITS file.  Attempts to find/parse jobs. """

        try:
            # Read the file (may need to raw read)
            print("Processing file "+file_path, file=sys.stderr)
            file_data = None
            with open(file_path, "rb") as f:
                file_data = f.read()

            # Parse as a qmgr database (support old and Win10 formats)
            jobs = []
            if BitsParser.is_qmgr_database(file_data):
                jobs = self.load_qmgr_jobs(file_data)
            elif BitsParser.is_qmgr10_database(file_data):
                jobs = self.load_qmgr10_jobs(file_data)

            # Try to "carve" jobs if the file is not a qmgr database (and carving is enabled)
            elif self.carve_all_files:
                if self.is_win_10:
                    jobs = self.carve_qmgr10_records(file_data)
                else:
                    jobs = self.load_non_qmgr_jobs(file_data)

            self.output_jobs(file_path, jobs)

        except Exception:
            print(f'Exception occurred processing file {file_path}: ' + traceback.format_exc(), file=sys.stderr)


    def determine_directory_architecture(self, path):
        """ Determines if the files within the directory suggest it came from a Windows 10 system or an older system """
        if os.path.exists(path + os.sep + "qmgr.db"):
            self.is_win_10 = True
        elif os.path.exists(path + os.sep + "qmgr0.dat"):
            self.is_win_10 = False


    def run(self):
        """ Finds and processes BITS database files """

        # If the queue "directory" is a file, just process the file
        if os.path.isfile(self.queue_dir):
            self.process_file(self.queue_dir)
            return

        # Determine if the directory appears to belong to a Windows 10 system or an older system for carving
        self.determine_directory_architecture(self.queue_dir)

        # List files in the queue directory and process
        for f in os.listdir(self.queue_dir):
            cur_path = self.queue_dir + os.sep + f
            if not os.path.isfile(cur_path):
                continue
            self.process_file(cur_path)


class BitsJob:
    """
    Provides methods for reformatting parsed jobs from the ANSSI-FR library
    """

    # Mappings between types returned by ANSSI-FR library and our output fields
    FILE_MAP = dict(
        src_fn="SourceURL",
        dest_fn="DestFile",
        tmp_fn="TmpFile",
        download_size="DownloadByteSize",
        transfer_size="TransferByteSize",
        vol_guid="VolumeGUID"
    )

    JOB_MAP = dict(
        job_id="JobId",
        type="JobType",
        priority="JobPriority",
        state="JobState",
        name="JobName",
        desc="JobDesc",
        cmd="CommandExecuted",
        args="CommandArguments",
        sid="OwnerSID",
        ctime="CreationTime",
        mtime="ModifiedTime",
        carved="Carved",
        files="Files",
        queue_path="QueuePath"
    )


    def __init__(self, job, bits_parser):
        """ Initialize a BitsJob with a parsed job dictionary and a reference to BitsParser """
        self.job = job
        self.bits_parser = bits_parser
        self.hash = None

        self.job_dict = {}
        if bits_parser.carve_db_files or bits_parser.carve_all_files:
            self.job_dict = {'Carved': False}

        self.parse()


    def is_useful_for_analysis(self, cur_dict=None):
        """ Returns True if the job contains at least one "useful" field (discards useless "carved" entries) and the ctime field exists """
        useful_fields = ['SourceURL', 'DestFile', 'TmpFile', 'JobId', 'JobState', 'CommandExecuted', 'CommandArguments']

        if not cur_dict:
            cur_dict = self.job_dict

        for k, v in cur_dict.items():
            if k in useful_fields and v:
                return True
            # Handle lists of dicts, like we have for the Files field
            if isinstance(v, list):
                for d in v:
                    if self.is_useful_for_analysis(d):
                        return True
        return False


    def is_carved(self):
        """ Simple function returns True if the job was carved """
        return self.job_dict.get('Carved') is True


    @staticmethod
    def escape(input_str):
        """ Simple escape function to eliminating non-printable characters from strings """
        if not isinstance(input_str, str) or input_str.isprintable():
            return input_str
        return ''.join(filter(lambda x: x in string.printable, input_str))


    def parse(self):
        """
        Converts the fields in self.job into format used for output and separates file entries.
        Does some formatting and type conversion.  Also computes a hash of the job for quick comparison.
        """

        file_fields = ['args', 'cmd', 'dest_fn', 'tmp_fn']
        job_hash = hashlib.md5()
        for k, v in self.job.items():
            # Map the attribute name, skip empty or unmapped values
            alias = self.JOB_MAP.get(k)
            if not alias:
                continue
            elif not v or str(v).strip() == '':
                continue

            # Convert timestamps into normal isoformat
            elif isinstance(v, datetime.datetime):
                self.job_dict[alias] = v.replace(microsecond=0).isoformat() + 'Z'

            # Convert boolean values to lowercase
            elif isinstance(v, bool):
                self.job_dict[alias] = str(v).lower()

            # If this is a SID, convert to username and set owner
            elif alias == self.JOB_MAP['sid']:
                self.job_dict[alias] = str(v)
                owner = self.bits_parser.get_username_from_sid(v)
                if owner:
                    self.job_dict["Owner"] = owner

            # The files field contains a list of files -- perform attribute mapping and environment variable resolution
            elif alias == self.JOB_MAP['files']:
                files_list = []
                for file in v:
                    file_dict = {}
                    for k1, v1 in file.items():

                        # Map the transaction attribute name, skip empty, unmapped, or invalid values
                        t_alias = self.FILE_MAP.get(k1)
                        if not t_alias:
                            continue
                        elif v1 is None or str(v1).strip() == '' or not str(v1).isprintable():
                            continue

                        # Skip certain invalid values (if there is no value or if the value is -1 (DWORD64))
                        if v1 is None or v1 == 0xFFFFFFFFFFFFFFFF:
                            continue

                        # If this is a file field, resolve and add to the list of files
                        if k1 in file_fields:
                            file_dict[t_alias] = os.path.expandvars(v1)
                        else:
                            file_dict[t_alias] = v1

                        # Update the object hash
                        job_hash.update(str(file_dict[t_alias]).encode('utf-8'))
                    files_list.append(file_dict)

                self.job_dict['Files'] = files_list
            else:
                self.job_dict[alias] = v

            # Escape non-printable chars if appropriate
            self.job_dict[alias] = self.escape(self.job_dict[alias])

            # Update the object hash
            if type(v) is not 'Dict':
                job_hash.update(str(v).encode('utf-8'))

        self.hash = job_hash.hexdigest()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--input', '-i', default='%ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader', help='Optionally specify the directory containing QMGR databases or the path to a file to process.')
    parser.add_argument('--output', '-o', help='Optionally specify a file for JSON output.  If not specified the output will be printed to stdout.')
    parser.add_argument('--carvedb', action='store_true', help='Carve deleted records from database files')
    parser.add_argument('--carveall', action='store_true', help='Carve deleted records from all other files')
    parsed_args = parser.parse_args()

    queue_dir = os.path.expandvars(parsed_args.input)
    bits_parser = BitsParser(queue_dir, parsed_args.carvedb, parsed_args.carveall, parsed_args.output)
    bits_parser.run()
