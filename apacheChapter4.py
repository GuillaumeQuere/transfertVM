from parentApache import ApacheChapterParent


class ApacheChapter4(ApacheChapterParent):

    def __init__(self, apache_bin, apache_dir, apache_conf, ssh_client):
        super(ApacheChapter4, self).__init__(apache_bin, apache_dir, apache_conf, ssh_client, "Chapter 4")
        self._list_method = [self._cis_4_1, self._cis_4_2, self._cis_4_3, self._cis_4_4]

    def __str__(self):
        return "Chapter: {}".format(self.chapter) + super(ApacheChapter4, self).__str__()

    def _cis_4_1(self):
		output1 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Require all denied" apache2.conf')
		output2 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Order" apache2.conf')
		output3 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Deny" apache2.conf')
		if(output1 !=""):
			standard = super(ApacheChapter4, self).cis_standard(
            	identity="CIS 4.1",
            	info="Deny Access to OS Directory",
            	level=1,
            	condition=output1["stdout"] == "Require all denied" ,
        	)
		else:
			standard = super(ApacheChapter4, self).cis_standard(
            	identity="CIS 4.1",
            	info="Deny Access to OS Directory",
            	level=1,
            	condition=(output2["stdout"]== "deny" or "allow") and (output3["stdout"]=="from all"),
        	)
		return standard

    def _cis_4_2(self):
		output1 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Require all denied" apache2.conf')
		output2 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Order" apache2.conf')
		output3 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Deny" apache2.conf')
		standard={}
		if(output2 =="" and output3==""):
			standard = super(ApacheChapter4, self).cis_standard(
            	identity="CIS 4.1",
            	info="Deny Access to OS Directory",
            	level=1,
            	condition=output1["stdout"] != "" ,
        		)
		else:
			standard = super(ApacheChapter4, self).cis_standard(
            	identity="CIS 4.1",
            	info="Deny Access to OS Directory",
            	level=1,
            	condition=output1["stdout"] != "",
        	)
		return standard

    def _cis_4_3(self):


	def _cis_4_4(self):
		output1 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Require all denied" apache2.conf')
		output2 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Order" apache2.conf')
		output3 = self.ssh_client.send_command(self.apache_bin + '/etc/apache2 grep "Deny" apache2.conf')



    def exec_cis(self):
        output = super(ApacheChapter4, self).parse_output()
        for method in self._list_method:
            try:
                tmp_out = method()
                output[self.chapter][tmp_out['id']] = {
                    'Info': tmp_out['info'],
                    'Level': tmp_out['level'],
                }
                if tmp_out['result']:
                    output[self.chapter][tmp_out['id']]['Score'] = "Correct"
                else:
                    output[self.chapter][tmp_out['id']]['Result'] = {
                        'Score': "Wrong",
                        'Remediation': tmp_out['remediation']

                    }
            except:
                output[method] = "Error"

        return output
