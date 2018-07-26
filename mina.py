import codecs
import io
import time
from argparse import ArgumentParser
from string import whitespace
import requests
import os
import hashlib
apikey = ''

vt_results = {}
sNo = 0
qcount = 0
num_lines = 0
hash = ''


def query(hash):

    global vt_results
    if not (len(hash) == 64 and int(hash, 32)):
        result = ''

    vt_query_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    post_params = {'apikey': apikey, 'resource': hash}
    print('Current hash: %s' % hash)
    time.sleep(15)
    global qcount
    qcount = qcount + 1
    data = ''
    try:
        vresponse = requests.post(vt_query_url, post_params)
    except:
       return query(hash)

    if vresponse.status_code == 204:
        print('Limit Exceeded, Trying in 60...')
        time.sleep(60)
        return query(hash)
    else:
        try:
            data = vresponse.json()
        except ValueError:
            result = ''
        if data['response_code'] == 1:
            if data['positives'] >= 1:
                print("detected by %s antiviruses" % data['positives'])
                result = "detected by %s antiviruses" % data['positives']
    try:
        vt_results[hash] = result
    except:
        result = ''
    return result


def csv(csv_file, report):

    global sNo
    global num_lines
    global hash
    susp_output = list()

    for num_lines, original_line in enumerate(io.open(csv_file, encoding='utf-16')):
        rep = original_line.strip(whitespace + '"').encode('utf-8')\
            .replace(', ', ' ').replace(' ,', ' ').strip().split(",")
        if "Verified" not in rep[7] and len(rep[16]) == 64:
            hash = rep[16]
            antiviruses_hits = query(hash)
            if "detected by" in antiviruses_hits:
                outputtext = "%s\n" \
                             "Time->     %s\n" \
                             "Location-> %s\n" \
                             "Entry->    %s\n" \
                             "Enabled->  %s\n" \
                             "Category-> %s\n" \
                             "Profile->  %s\n" \
                             "Descr->    %s\n" \
                             "Company-> %s\n" \
                             "FilePath-> %s\n" \
                             "Version-> %s\n" \
                             "LaunchPath-> %s\n" \
                             "MD5-> %s\n" \
                             "SHA256-> %s\n" \
                             "\n" % (
                                 antiviruses_hits,
                                 rep[0], rep[1], rep[2],  rep[3],  rep[4],  rep[5], rep[7],
                                 rep[8], rep[9], rep[10], rep[11], rep[12], rep[16],)
                susp_output.append(outputtext)
                sNo = sNo + 1
    report.append('Report\n')
    for event in susp_output:
        report.append(event)


if __name__ == '__main__':
    if apikey == '':
        print('null api key')
        exit(1)
    report = list()
    parser = ArgumentParser()
    parser.add_argument('--csv',    metavar='Path', type=str, help='relative or full path of csv')
    parser.add_argument('--rpath',  metavar='Path', type=str, help='root path')
    args = parser.parse_args()

    if args.rpath is not None:
        for a, b, c in os.walk(args.rpath ):
            for d in c:
                if d.endswith('.exe') or d.endswith('.dll'):
                    try:
                        openedFile = open(a+d)
                    except:
                        continue
                    readFile = openedFile.read()
                    try:
                        report.append(a+d)
                        report.append(query(hashlib.sha1(readFile).hexdigest()))
                        report.append('\n')
                    except:
                        pass

    if args.csv is not None:
        try:
            csv(args.csv, report)
        except:
            raise ImportError
        num_lines = num_lines + 1
        print(' STATISTICS\n')
        print(' %s autorun entries' % num_lines)
        print(' %s entries in VirusTotal' % qcount)
        print(' %s possible malicious autorun entries' % sNo)
    try:
        codecs.open('output.txt', 'w', 'utf-8').write('\r\n'.join(report))
    except:
        codecs.open('output.txt', 'w').write('\r\n'.join(report))
