# Setup server  on CentOS 6.5 (Digital Ocean)

from __future__ import with_statement
from fabric.api import run, sudo, settings, put, cd

admin_user_name = 'admin'
admin_email = 'admin@example'

def host_type():
    run('uname -s')

def update_system():
    sudo('yum update -y ')
    sudo('yum upgrade -y')
    # install and configure automatic updates
    sudo('yum install -y yum-cron')
    sudo('chkconfig yum-cron on')
    sudo("sed -i'.old' 's/^MAILTO=/MAILTO="+admin_email+"/' /etc/sysconfig/yum-cron")
    sudo("echo 'ERROR_LEVEL=1' >> /etc/sysconfig/yum-cron")

    sudo('rpm -Uvh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm')
    sudo('rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-6.rpm')

def install_base_soft():
    sudo('yum install -y vim curl rsy')

def secure_system(ssh_key,ssh_users):
    sudo('yum install -y fail2ban')
    sudo ('cp /etc/fail2ban/jail.{conf,local}')

#
#     !!! create user with password "simplepassword1234".
#     Please, change it at first login!!!
#
#
    sudo('useradd -s /bin/bash -p "pacHXCdIdvdUw" -m %s' % admin_user_name)
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

    sudo("echo 'AllowUsers " + ssh_users +"' >> /etc/ssh/sshd_config")

    # Add admin to sodoers
    sudo("echo 'admin   ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")


def install_firewall():
    # config iptables
    put('configs/rules', '/etc/sysconfig/iptables', use_sudo=True)
    sudo('service iptables restart')


def install_mysql():

    sudo('yum install -y mysql mysql-server')
    sudo('/etc/init.d/mysqld restart')

#sudo /usr/bin/mysql_secure_installation


def install_nginx():
    sudo("yum install -y nginx")
    sudo("/etc/init.d/nginx start")
    sudo('yum --enablerepo=remi install -y php-fpm php-mysql')

    sudo("sed -i'.old' 's/cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/' /etc/php.ini")
    sudo("sed -i'.old' 's/^user = apache/user = nginx/' /etc/php-fpm.d/www.conf")
    sudo("sed -i'.old' 's/^group = apache/group = nginx/' /etc/php-fpm.d/www.conf")
    sudo('service php-fpm restart')

    put('configs/nginx_site1', '/etc/nginx/conf.d/default.conf', use_sudo=True, mode=0755)
    sudo('chown root:root /etc/nginx/conf.d/default.conf')
    put('configs/info.php', '/usr/share/nginx/html/info.php', use_sudo=True, mode=0755)
    sudo('chown root:root /usr/share/nginx/html/info.php')
    sudo("service nginx restart")

    sudo("chkconfig --levels 235 mysqld on")
    sudo("chkconfig --levels 235 nginx on")
    sudo("chkconfig --levels 235 php-fpm on")


def secure_nginx():
    print('done')


def install_mail(email_address):
    sudo ('yum install -y postfix')
    sudo ('chkconfig --levels 235 postfix on')

    sudo ('yum install -y mailx')
    sudo ('ln -s /bin/mailx /bin/email')
    sudo ('echo "Your message" | mail -s "Message Subject" ' + email_address)



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

def do_it(ssh_key = '',ssh_users='admin' ):
    ssh_key = open('key.pub').read()
    update_system()
    secure_system(ssh_key, ssh_users)
    install_firewall()
    install_base_soft()
    install_mysql()
    install_nginx()

def test1():
    install_base_soft()
    install_mysql()
    install_nginx()


