#!/usr/bin/python

# -*- coding: utf-8 -*-

import os

import re

from multiprocessing.dummy import Pool as ThreadPool

import sys

import time

import pexpect

# 规则列表

rulelist = ['\.\./', 'select.+(from|limit)', '(?:(union(.*?)select))', 'having|rongjitest', 'sleep\((\s*)(\d*)(\s*)\)',

            'benchmark\((.*)\,(.*)\)', 'base64_decode\(', '(?:from\W+information_schema\W)',

            '(?:(?:current_)user|database|schema|connection_id)\s*\(', '(?:etc\/\W*passwd)',

            'into(\s+)+(?:dump|out)file\s*', 'group\s+by.+\(', 'xwork.MethodAccessor',

            '(?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|alert|showmodaldialog)\(',

            'xwork\.MethodAccessor', '(gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data)\:\/',

            'java\.lang', '\$_(GET|post|cookie|files|session|env|phplib|GLOBALS|SERVER)\[',

            '\<(iframe|script|body|img|layer|div|meta|style|base|object|input)', '(onmouseover|onerror|onload)\=',

            '.(bak|inc|old|mdb|sql|backup|java|class)$', '\.(svn|htaccess|bash_history)',

            '(vhost|bbs|host|wwwroot|www|site|root|hytop|flashfxp).*\.rar',

            '(phpmyadmin|jmx-console|jmxinvokerservlet)', 'java\.lang',

            '/(attachments|upimg|images|css|uploadfiles|html|uploads|templets|static|template|data|inc|forumdata|upload|includes|cache|avatar)/(\\w+).(php|jsp)']

SSH_PASSWD = 'toor' #webserver密码

def Auto_scp():

    cmd = ['scp -r root@192.168.188.131:/var/log/snort/* log-2016-07-28/40/',

           'scp -r root@192.168.188.131:/var/log/*.log log-2016-07-28/39/'

           ]

    for line in cmd:

        child = pexpect.spawn(line,timeout=300)

        child.expect('password:')

        child.sendline(SSH_PASSWD)

        child.expect(pexpect.EOF)

    return True

def File_Search(filepath):

    filelist = []

    for lists in os.listdir(filepath):

        path = os.path.join(filepath, lists)

        if os.path.isfile(path):

            filelist.append(path)

        if os.path.isdir(path):

            File_Search(path)

    pool = ThreadPool(50)

    results = pool.map(Log_Analysis, filelist)

    pool.close()

    pool.join()

def Log_Analysis(filename):

    content = open(filename).read()

    r = open('result.txt', 'a') #需要本地先新建个result.txt文件

    r.write('\n' + '=================== web_log_secAnalysis ===================' + '\n' + filename + '\n')

    for regex in rulelist:

        result_tmp = re.compile(regex,re.IGNORECASE).findall(content)

        if result_tmp:

            r.write(str(result_tmp) + '\n' )

    return 'True'

if __name__ == '__main__':

    if len(sys.argv) < 2:

        print "Usage: log_SecAnalysis.py filepath"

        sys.exit(0)

    else:

        if Auto_scp():

            start = time.clock()

            print '====> Log is analyzing, please wait for a moment <==== '

            File_Search(sys.argv[1])

            end = time.clock()

            print '分析完毕,共运行时长:' + str(end - start)

            sys.exit(0)

        else:

            print '文件scp传输异常...'