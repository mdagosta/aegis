# README #

This code is your shield, your [Aegis](https://en.wikipedia.org/wiki/Aegis), to carry with you into battle on the brave new web.


### Use the command line tools ###

* Use as a cloned repository: `virtualenv --python=``which python3`` virtualenv`
* `./virtualenv/bin/activate`
* `aegis debug`


### Use in aegis application ###

* `aegis create app_name`
* How to do something with your aegis app
* Updating
* Debugging


### Create new Pypi release ###

* Follow along here: https://packaging.python.org/tutorials/packaging-projects/
* Being in virtualenv is not required
* Update version in setup.py 0.0.X
* git tag 0.0.X
* python3 -m pip install --user --upgrade setuptools wheel
* python3 setup.py sdist bdist_wheel
* python3 -m pip install --user --upgrade twine
* python3 -m twine upload dist/*

* Keyring error needs: pip3 install --upgrade keyrings.alt --user
