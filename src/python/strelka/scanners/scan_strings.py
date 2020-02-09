import re
import io
import os
import subprocess
import sys
import shlex
import uuid

from strelka import strelka


class ScanStrings(strelka.Scanner):
    """Collects strings from files.

    Collects strings from files (similar to the output of the Unix 'strings'
    utility).

    Options:
        limit: Maximum number of strings to collect, starting from the
            beginning of the file. If this value is 0, then all strings are
            collected.
            Defaults to 0 (unlimited).
    """
    def init(self):
        self.strings_regex = re.compile(br'[^\x00-\x1F\x7F-\xFF]{4,}')

    def scan(self, data, file, options, expire_at):
        limit = options.get('limit', 0)

        #strings = self.strings_regex.findall(data)
        #if limit:
        #    strings = strings[:limit]
        #self.event['strings'] = strings
        tempfolder = options.get('outdir', '/scanworkdir/')
        with io.BytesIO(data) as data_stream:
            temporarylocation=tempfolder + file.uid
            with open(temporarylocation,'wb') as out: ## Open temporary file as bytes
                out.write(data_stream.read())         ## Read bytes into file

            ## Do stuff with module/file
            #flarestrings /data/malware | rank_strings --scores > /data/interesting.txt
            outfile = "flare-" + uuid.uuid4().hex
            cmd = "flarestrings " + temporarylocation + " | rank_strings --scores"
            if limit > 0:
                cmd = cmd + " --limit " + str(limit) 
            
            cmd = cmd + " > " + tempfolder + outfile

            ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = ps.communicate()[0]

            #if limit:
            #    output = output[:limit]
            
            self.event['strings_outfile'] = outfile #output
            # print(output)
            os.remove(temporarylocation) ## Delete file when done
           

