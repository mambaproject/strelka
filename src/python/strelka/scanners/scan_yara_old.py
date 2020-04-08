import glob
import os
import yara

from strelka import strelka

class ScanYaraOld(strelka.Scanner):
    """Scans files with YARA.

    Attributes:
        compiled_yara: Compiled YARA file derived from YARA rule file(s)
            in location.

    Options:
        location: Location of the YARA rules file or directory.
            Defaults to '/etc/yara/'.
        meta: List of YARA rule meta identifiers
            (e.g. 'Author') that should be logged.
            Defaults to empty list.
    """
    def init(self):
        self.compiled_yara = None

    def scan(self, data, file, options, expire_at):
        location = options.get('location', '/etc/yara/')
        meta = options.get('meta', [])

        try:
            if self.compiled_yara is None:
                if os.path.isdir(location):
                    yara_filepaths = {}
                    #globbed_yara_paths = glob.iglob(f'{location}/**/*.yar*', recursive=True)
                    globbed_yara_paths = glob.iglob(f'{location}/*.yar*', recursive=False)
                    for (idx, entry) in enumerate(globbed_yara_paths):
                        yara_filepaths[f'namespace_{idx}'] = entry
                    self.compiled_yara = yara.compile(filepaths=yara_filepaths)

                else:
                    self.compiled_yara = yara.compile(filepath=location)

        except (yara.Error, yara.SyntaxError):
            self.flags.append('compiling_error')

        self.event['matches'] = []
        self.event['strings'] = []

        try:
            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data)
                for match in yara_matches:
                    self.event['matches'].append(match.rule)

                    #for k, v in match.meta.items():
                    #    if meta and k not in meta:
                    #        continue
                    #    self.event['meta'].append({
                    #        'rule': match.rule,
                    #        'identifier': k,
                    #        'value': v,
                    #    })
                    
                    # 'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
                    # (<offset>, <string identifier>, <string data>)
                    for s in match.strings:
                        self.event['strings'].append({
                            'rule': match.rule,
                            'offset': s[0],
                            'identifier': s[1],
                            'data': s[2],
                        })

        except (yara.Error, yara.TimeoutError):
            self.flags.append('scanning_error')
