TP-LINK1043nd V4

* Build requirements

* Setup

It seems that certain Makefiles/scripts inside the repo have absolute paths 
to other build folders. We can modify each path by hand, or just use the 
user and paths we assume they used.

** Create an user 'jji315' and link '/home/jji315/mount1/qca_branch' to the 
'src' folder inside this repo.

$ chmod o+rwx 1043ndv4
$ sudo adduser jji315
$ sudo adduser jji315 sudo # We'll need that later on
$ su - jji315
$ mkdir mount1
$ cd mount1
$ ln -s /path/to/1043ndv4/src qca_branch
$ cd qca_branch
$ pwd
/home/jji315/mount1/qca_branch
$ ls | head -3
ap152
apps
build

