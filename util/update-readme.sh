#!/bin/sh

perl util/wiki2pod.pl README.mediawiki > /tmp/a.pod && pod2text /tmp/a.pod > README.txt
