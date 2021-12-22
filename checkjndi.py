#!/usr/bin/env python3

import os
import zipfile
import io
import argparse

foundvulnerable = False

def process_jarfile_content(zf, filetree):
    '''

    Recursively look in zf for the class of interest or more jar files
    Print the hits
    zf is a zipfile.ZipFile object
    '''
    ispatched = False
    hasjndi = False
    global foundvulnerable
    for f in zf.namelist():
        if os.path.basename(f) == 'JndiLookup.class':
            # found one, print it
            filetree_str = ' contains '.join(filetree)
            hasjndi = True
            jndilookupbytes = zf.read(f)
            if b'JNDI is not supported' in jndilookupbytes:
                # 2.12.2 is patched
                # https://github.com/apache/logging-log4j2/commit/70edc233343815d5efa043b54294a6fb065aa1c5#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR37
                ispatched = True
        elif os.path.basename(f) == 'MessagePatternConverter.class':
            mpcbytes = zf.read(f)
            if b'Message Lookups are no longer supported' in mpcbytes:
                # 2.16 is patched
                # https://github.com/apache/logging-log4j2/commit/27972043b76c9645476f561c5adc483dec6d3f5d#diff-22ae074d2f9606392a3e3710b34967731a6ad3bc4012b42e0d362c9f87e0d65bR97
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
        print('%s contains "JndiLookup.class" ** BUT APPEARS TO BE PATCHED **' % filetree_str)
    elif hasjndi:
        foundvulnerable = True
        print('WARNING: %s contains "JndiLookup.class"' % filetree_str)


def do_jarfile_from_disk(fpath):
    try:
        zf = zipfile.ZipFile(fpath)
    except:
        return
    process_jarfile_content(zf, filetree=[fpath,])


def main(topdir):
    for root, dirs, files in os.walk(topdir, topdown=True):
        dirs[:] = filter(lambda dir: not os.path.ismount(os.path.join(root, dir)), dirs)
        for name in files:
            if not (name.lower().endswith('.jar') or name.lower().endswith('.war') or name.lower().endswith('.ear') or name.lower().endswith('.zip') or name.endswith('JndiLookup.class')):
                # skip non-jars
                continue
            if (os.path.basename(name) == "JndiLookup.class"):
                print("WARNING: %s *IS* JndiLookup.class" % os.path.join(root,name))
            else:
                jarpath = os.path.join(root, name)
                do_jarfile_from_disk(jarpath)
    if not foundvulnerable:
        print("No vulnerable components found")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scanner for jars that may be vulnerable to CVE-2021-44228')
    parser.add_argument('dir', nargs='?', help='Top-level directory to start looking for jars', default='.')
    args = vars(parser.parse_args())
    main(args['dir'])
