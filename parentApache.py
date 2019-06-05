

class ApacheChapterParent(object):
    def __init__(self, apache_bin, apache_dir, apache_conf, ssh_client, chapter):
        self.apache_bin = apache_bin
        self.apache_dir = apache_dir
        self.apache_conf = self.apache_dir + '/' + apache_conf
        self.chapter = chapter
        self.ssh_client = ssh_client

    def __str__(self):
        return "Python class of methods of the Chapter {}\n The Apache configurations are : \n " \
               "-Apache bin: {}\n-Conf file: {}".format(self.chapter, self.apache_bin, self.apache_conf)

    def cis_standard(self, info, description, level, remediation,condition):
        standard = {
            'info': info,
            'extrainfo': description if description is not None else "Not indicate",
            'level': level,
            'result': True if condition is True else False,
            'remediation': remediation if remediation is not None else "Not indicate"
        }
        return standard
