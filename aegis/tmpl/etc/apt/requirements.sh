#!/bin/bash
#
# Just to install apt dependencies listed in requirements.apt

for pkg in `cat ./requirements.apt`; do sudo apt install $pkg; done
