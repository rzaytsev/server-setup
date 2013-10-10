# Install LNMP stack on Ubuntu 12.04.3 LTS (Digital Ocean)

from __future__ import with_statement
from fabric.api import run, sudo, settings, put

ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOPy33dQ6dy6dU5jn8GKM/cXCkvdwDtLsi8ChQvREHl8cnIQNuD2upnnuBov3LgiuuexUE8A44S4MAhmMr7gBxtmBH6I/Md6Afsnaj1wGS00sC4qgHbfixylHyOZvTK1+tLa9TWepGuOguOnjPR/yyzcIYs8nXPMGq2f2AthFt13fpvc2UI18yli8+NENScVkgZ52vGsj3A7qgOBMHiCwVUcxyroc/NFjDKL9JkyyWcC4QImz7LtNTIsueWdrbkvaUjRrK0mKzqHxvninznJC6TQ4xBMqK2SUPEru6Pe0X5OZ5191k39e1SkChWbjTOnW05ZXDbGBgBJE1PFts4TYB servers's key"
admin_user_name = 'admin'
mysql_password = "simplepassword1234"

def host_type():
    run('uname -s')

def update_system():
    sudo('apt-get update')
    sudo('apt-get upgrade')
    sudo('apt-get install unattended-upgrades')

# configure unattended-upgrades
#   sudo dpkg-reconfigure -plow unameattended-upgrades

def install_base_soft():
    sudo('apt-get install -y vim')


def secure_system():
    sudo('apt-get install fail2ban')
    sudo ('cp /etc/fail2ban/jail.{conf,local}')


# create user with password "simplepassword1234". Please, change it at first login!!!
    sudo('useradd -U -s /bin/bash -p "pacHXCdIdvdUw" -m %s' % admin_user_name)
    sudo('mkdir /home/%s/.ssh' % admin_user_name)
    sudo('chmod 700 /home/%s/.ssh' % admin_user_name)
    sudo('echo "%s" >> /home/%s/.ssh/authorized_keys' % (ssh_key, admin_user_name))
    sudo('chmod 400 /home/%s/.ssh/authorized_keys' % admin_user_name)
    sudo('chown %s:admin /home/%s -R' % (admin_user_name,admin_user_name))

#config sshd
#PermitEmptyPasswords no

    sudo("sed -i'.old' 's/^PermitRootLogin [Yy]es/PermitRootLogin no/' /etc/ssh/sshd_config")
    with settings(warn_only=True):
            if run('cat /etc/ssh/sshd_config | grep -e "^PasswordAuthentication [Yy]es"').failed:
                sudo("echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config")
            else:
                sudo("sed -i'.old' 's/^PasswordAuthentication [Yy]es/PasswordAuthentication no/' /etc/ssh/sshd_config")

    sudo("echo 'AllowUsers admin' >> /etc/ssh/sshd_config")

    # config iptables
    sudo('mkdir /etc/iptables')
    put('configs/rules', '/etc/iptables', use_sudo=True)

def install_mysql():
    sudo("echo mysql-server-5.1 mysql-server/root_password password %s | debconf-set-selections" % (mysql_password) )
    sudo("echo mysql-server-5.1 mysql-server/root_password_again password %s | debconf-set-selections" % (mysql_password) )
    sudo("apt-get -y install mysql-server")
    sudo("mysql_install_db")
# ? sudo /usr/bin/mysql_secure_installation


def install_nginx():
    sudo("apt-get -y install nginx")
    sudo("service nginx start")
    public_ip_address = sudo("ifconfig eth0 | grep inet | awk '{ print $2 }'")
    print public_ip_address

def do_it():
    update_system()
    secure_system()
    install_base_soft()
    install_mysql()
    install_nginx()

def test2():
    #sudo('mkdir /etc/iptables')
    put('configs/rules', '/etc/iptables', use_sudo=True, mode=0700)
    sudo('chown root:root /etc/iptables/ -R ')
