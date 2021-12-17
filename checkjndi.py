#!/usr/bin/env python3

import os
import zipfile
import io
import argparse

def process_jarfile_content(zf, filetree):
    '''

    Recursively look in zf for the class of interest or more jar files
    Print the hits
    zf is a zipfile.ZipFile object
    '''
    ispatched = False
    hasjndi = False
    for f in zf.namelist():
        if os.path.basename(f) == 'JndiLookup.class':
            # found one, print it
            filetree_str = ' contains '.join(filetree)
            hasjndi = True
            jndilookupbytes = zf.read(f)
            if b'JNDI is not supported' in jndilookupbytes:
                ispatched = True
        elif os.path.basename(f) == 'MessagePatternConverter.class':
            mpcbytes = zf.read(f)
            if b'Message Lookups are no longer supported' in mpcbytes:
                ispatched = True
        elif os.path.basename(f).lower().endswith(".jar") or os.path.basename(f).lower().endswith(".war") or os.path.basename(f).lower().endswith(".ear") or os.path.basename(f).lower().endswith(".zip"):
            # keep diving
            try:
                new_zf = zipfile.ZipFile(io.BytesIO(zf.read(f)))
            except:
                continue
            new_ft = list(filetree)
            new_ft.append(f)
            process_jarfile_content(new_zf, new_ft)
    if hasjndi and ispatched:
        print(filetree_str,'contains "JndiLookup.class" ** BUT APPEARS TO BE PATCHED **')
    elif hasjndi:
        print("WARNING: ", filetree_str,'contains "JndiLookup.class"')


def do_jarfile_from_disk(fpath):
    try:
        zf = zipfile.ZipFile(fpath)
    except:
        return
    process_jarfile_content(zf, filetree=[fpath,])


def main(topdir):
    for root, dirs, files in os.walk(topdir, topdown=False):
        for name in files:
            if not (name.lower().endswith('.jar') or name.lower().endswith('.war') or name.lower().endswith('.ear') or name.lower().endswith('.zip') or name.endswith('JndiLookup.class')):
                # skip non-jars
                continue
            if (os.path.basename(name) == "JndiLookup.class"):
                print("WARNING: %s *IS* JndiLookup.class" % os.path.join(root,name))
            else:
                jarpath = os.path.join(root, name)
                do_jarfile_from_disk(jarpath)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scanner for jars that may be vulnerable to CVE-2021-44228')
    parser.add_argument('dir', nargs='?', help='Top-level directory to start looking for jars', default='.')
    args = vars(parser.parse_args())
    main(args['dir'])
