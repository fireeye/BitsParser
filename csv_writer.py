import csv
import os


DEFAULT_VALUES = (
    ('JobId', None),
    ('JobName', None),
    ('JobType', None),
    ('JobPriority', None),
    ('OwnerSID', None),
    ('JobState', None),
    ('CommandExecuted', None),
    ('CommandArguments', None),
    ('FileID', 0),
    ('DestFile', None),
    ('SourceURL', None),
    ('TmpFile', None),
    ('DownloadByteSize', -1),
    ('TransferByteSize', -1),
    ('VolumeGUID', None),
    ('CreationTime', None),
    ('ModifiedTime', None),
    ('Carved', False)
)

def flattener(job):

    def _f(index, file):
        rv = {k: file.get(k, job.get(k, v))  for k, v in DEFAULT_VALUES}
        rv['FileID'] = index
        return rv

    files = job.get('Files', [])

    if files:
        return [_f(index, f) for index, f in enumerate(files)]

    return [_f(0, {})]


def write_csv(filename, records):
    """Write records to a CSV file."""
    if not len(records):
        return
    if os.path.isfile(filename):
        csvfile = open(filename, "a+", newline='', encoding='utf-8')
    else:
        csvfile = open(filename, "w", newline='', encoding='utf-8')

    writer = csv.DictWriter(csvfile, fieldnames=[k for k, _ in DEFAULT_VALUES])
    writer.writeheader()
    for r in records:
        for sub_r in flattener(r):
            writer.writerow(sub_r)
    csvfile.close()
