'''
Created on 2013. 7. 17.

@author: Administrator
'''
import postfile
import simplejson
import urllib
import urllib2
apikey = ""
def get_resource(file_name):
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey",apikey)]
        file_to_send = open(file_name, "rb").read()
        files = [("file", file_name, file_to_send)]
        json = postfile.post_multipart(host, selector, fields, files)
        l = json.split()
        re = l[5]
        re = re.strip("\"")
        re = re.strip(",")
        re = re.strip("\"")
        return re
def get_vt_cnt(file_name):
        url = "http://www.virustotal.com/api/get_submitted_file_report.json"
        parameters = {"resource": get_resource(file_name),"key": apikey}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url,data)
        response = urllib2.urlopen(req)
        json = response.read()
        response_dict = simplejson.loads(json)
        res = response_dict.get("report")
        cnt=0
        l = res[1].values()
        for i in l:
                if i !='':
                        cnt +=1
        return cnt
if __name__ == '__main__':
    print get_vt_cnt("S:\\python27\\code\\test.txt")
    pass
    