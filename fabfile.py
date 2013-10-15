# Install LNMP stack on Ubuntu 12.04.3 LTS (Digital Ocean)

from __future__ import with_statement
from fabric.api import run, sudo, settings, put, cd

ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOPy33dQ6dy6dU5jn8GKM/cXCkvdwDtLsi8ChQvREHl8cnIQNuD2upnnuBov3LgiuuexUE8A44S4MAhmMr7gBxtmBH6I/Md6Afsnaj1wGS00sC4qgHbfixylHyOZvTK1+tLa9TWepGuOguOnjPR/yyzcIYs8nXPMGq2f2AthFt13fpvc2UI18yli8+NENScVkgZ52vGsj3A7qgOBMHiCwVUcxyroc/NFjDKL9JkyyWcC4QImz7LtNTIsueWdrbkvaUjRrK0mKzqHxvninznJC6TQ4xBMqK2SUPEru6Pe0X5OZ5191k39e1SkChWbjTOnW05ZXDbGBgBJE1PFts4TYB servers's key"
admin_user_name = 'admin'
mysql_password = "simplepassword1234"

def host_type():
    run('uname -s')

def update_system():
    sudo('apt-get update -y ')
    #sudo('apt-get upgrade -y')
    sudo('apt-get install -y unattended-upgrades')
    put('configs/10periodic', '/etc/apt/apt.conf.d/10periodic', use_sudo=True, mode=0700)
    sudo('chown root:root /etc/apt/apt.conf.d/10periodic ')


def install_base_soft():
    sudo('apt-get install -y vim')
    #sudo('apt-get install -y logwatch')
    #sudo('echo "/usr/sbin/logwatch --output mail --mailto admin@example.com --detail high" > /etc/cron.daily/00logwatch')

def secure_system():
    sudo('apt-get install -y fail2ban')
    sudo ('cp /etc/fail2ban/jail.{conf,local}')

    # !!! create user with password "simplepassword1234". Please, change it at first login!!!
    sudo('useradd -g admin -s /bin/bash -p "pacHXCdIdvdUw" -m %s' % admin_user_name)
    sudo('mkdir /home/%s/.ssh' % admin_user_name)
    sudo('chmod 700 /home/%s/.ssh' % admin_user_name)
    sudo('echo "%s" >> /home/%s/.ssh/authorized_keys' % (ssh_key, admin_user_name))
    sudo('chmod 400 /home/%s/.ssh/authorized_keys' % admin_user_name)
    sudo('chown %s:admin /home/%s -R' % (admin_user_name,admin_user_name))

    #config sshd
    sudo("sed -i'.old' 's/^PermitEmptyPasswords [Yy]es/PermitEmptyPasswords no/' /etc/ssh/sshd_config")
    sudo("sed -i'.old' 's/^PermitRootLogin [Yy]es/PermitRootLogin no/' /etc/ssh/sshd_config")
    with settings(warn_only=True):
            if run('cat /etc/ssh/sshd_config | grep -e "^PasswordAuthentication [Yy]es"').failed:
                sudo("echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config")
            else:
                sudo("sed -i'.old' 's/^PasswordAuthentication [Yy]es/PasswordAuthentication no/' /etc/ssh/sshd_config")

    sudo("echo 'AllowUsers vagrant admin' >> /etc/ssh/sshd_config")

    # config iptables
    sudo('mkdir /etc/iptables')
    put('configs/rules', '/etc/iptables', use_sudo=True)
    sudo('echo "#!/bin/sh" >> /etc/network/if-pre-up.d/iptables')
    sudo('echo "iptables-restore < /etc/iptables/rules" >> /etc/network/if-pre-up.d/iptables')
    sudo('chmod +x /etc/network/if-pre-up.d/iptables')


def install_mysql():
    sudo("echo mysql-server-5.1 mysql-server/root_password password %s | debconf-set-selections" % (mysql_password) )
    sudo("echo mysql-server-5.1 mysql-server/root_password_again password %s | debconf-set-selections" % (mysql_password) )
    sudo("apt-get -y install mysql-server libapache2-mod-auth-mysql php5-mysql")
    sudo("mysql_install_db")
# ? sudo /usr/bin/mysql_secure_installation


def install_nginx():
    sudo("apt-get -y install nginx php5-fpm")
    sudo("service nginx start")

    sudo("sed -i'.old' 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' /etc/php5/fpm/php.ini")
    sudo("sed -i'.old' 's/listen = 127\.0\.0\.1\:9000/listen = \/var\/run\/php5-fpm.sock/' /etc/php5/fpm/pool.d/www.conf")
    sudo('sudo service php5-fpm restart')

    put('configs/nginx_site1', '/etc/nginx/sites-available/site1', use_sudo=True, mode=0755)
    sudo('chown root:root /etc/nginx/sites-available/site1')
    sudo('ln -s /etc/nginx/sites-available/site1 /etc/nginx/sites-enabled/site1')
    sudo('rm /etc/nginx/sites-enabled/default')
    put('configs/info.php', '/usr/share/nginx/www/info.php', use_sudo=True, mode=0755)
    sudo('chown root:root /usr/share/nginx/www/info.php')
    sudo("service nginx restart")


def install_webasyst():
    #sudo('apt-get -y install git')
    path = '/usr/share/nginx/www/webasyst/'
    sudo('mkdir '+ path)
    with cd(path):
        run('pwd')
        sudo('git clone git://github.com/webasyst/webasyst-framework.git')
        with cd(path + 'webasyst-framework/wa-config'):
            run('pwd')
            sudo ('cp apps.php.example apps.php')
            sudo('cp config.php.example config.php')
            sudo('cp db.php.example db.php')
            sudo('cp locale.php.example locale.php')
            sudo('cp SystemConfig.class.php.example SystemConfig.class.php')
    sudo ('chmod 0775 '+path)

def create_ssl_site(site_name = 'example'):
    ssl_dir = '/etc/nginx/ssl'
    with settings(warn_only=True):
        if run("test -d %s" % ssl_dir).failed:
            sudo('mkdir %s' % ssl_dir)
    with cd(ssl_dir):
        sudo ('openssl genrsa -des3 -out '+site_name+'.key 1024')
        sudo ('sudo openssl req -new -key '+site_name+'.key -out '+site_name+'.csr')
        sudo('cp '+site_name+'.key '+site_name+'.key.org')
        sudo('openssl rsa -in '+site_name+'.key.org -out '+site_name+'.key')
        sudo('openssl x509 -req -days 365 -in '+site_name+'.csr -signkey '+site_name+'.key -out '+site_name+'.crt')
    put('configs/example_ssl','/etc/nginx/sites-available/'+site_name, use_sudo=True, mode=0755)
    sudo("sed -i'.old' 's/\*name\*/"+site_name+"/' /etc/nginx/sites-available/"+site_name)
    sudo('ln -s /etc/nginx/sites-available/'+site_name+' /etc/nginx/sites-enabled/'+site_name+'')
    sudo("service nginx restart")

def do_it():
    update_system()
    secure_system()
    install_base_soft()
    install_mysql()
    install_nginx()


