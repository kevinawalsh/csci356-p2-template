# This is a fabric2 configuration file for deploying and running code in
# the cloud.
#
# Author: kwalsh@cs.holycross.edu
# Date: January 25, 2015.
# Updated: October 18, 2020.
#
# To use this file, you need to have the `fab` command installed from the
# fabric3 package (see: https://pypi.org/project/Fabric3/). You can either:
#
# (a) Rely on the copy I have installed on all of our Google Cloud and Amazon
#     Cloud servers. Copy your code to any cloud machine by either loging in and
#     running `git clone` and/or `git pull` and `git update`, or transfer your
#     code using `scp` directly from your own laptop. Then log in to the cloud
#     machine using ssh and run the `fab` commands from there.
# (b) Or, install Fabric3 on your own computer and run the `fab` commands from
#     your own local terminal.
#
# To deploy code to all cloud hosts, run this command:
#    fab -P deploy
# To run the code on all cloud hosts, run this command on radius:
#    fab -P start
# To do both, run this command on radius:
#    fab -P deploy start
#
# You can edit this file however you like, but update the instructions above if
# you do so that it is clear how to deploy and start your geoanalyze service.

from fabric.api import hosts, run, env
from fabric.operations import put

# This is the cloud_sshkey needed to log in to other servers. If running fabric
# from your laptop, your key is probably named ~/.ssh/cloud_sshkey. But if
# you are running fabric from within the cloud, it is probably named
# ~/.ssh/id_rsa instead.
env.key_filename = '~/.ssh/cloud_sshkey'
# env.key_filename = '~/.ssh/id_rsa'

# This is the list of cloud hosts. Add or remove from this list as you like.
env.hosts = [
        '34.94.207.48', # gcp - bogoserver
        '35.228.5.242', # gcp - floppybird
        '54.235.59.70', # aws - randoserver
        '3.96.172.100', # aws - uncreatively
        ]
# This is the host designated as the central coordator. Pick whichever server
# from all_hosts you like here. By default, just take the first one.
central_host = env.hosts[0]

# The deploy task copies all python files from local directory to every host.
# If you want to copy other files, you can modify this, or make a separate task
# for deploying the other files to specific hosts.
def deploy():
    run('mkdir -p ~/fabdeploy/')
    put('*.py', '~/fabdeploy/')

# The start task runs the geoanalyze.py command on every host.
def start():
    run('python3 ~/fabdeploy/geoanalyze.py ' + central_host + ' 8088')

