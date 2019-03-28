# encoding=utf8
import re
import urllib
import urlparse
import xml
import requests
from setting import *

# DBMS ERROR XML
ERROR_DBMS_XML = "xml/errors.xml"

SENSITIVE_HEADER_DICT = {'Host':'127.0.0.1','Client-IP': '127.0.0.1','X-Forwarded-For': '127.0.0.1','X-Forwarded-Host': '127.0.0.1','Referer':'http://www.google.com/search?hl=en&q=testing','User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21'}
WHITE_HEADER_LIST = ['Cookie','Cache-Control','Pragma','Connection','Upgrade-Insecure-Requests','Accept','Accept-Language','Accept-Encoding','If-None-Match','If-Modified-Since']
# module-> m ，但是m不太好匹配
SENSITIVE_PARAM_LIST = ['file','path','page','home','dir','url','temple','down','module','name']



class FileReadChecker:
    # 参数
    param_tupe = ''
    value_tupe = ''
    param = ''
    value = ''

    #payload
    payload = ''
    regexp = ''

    #返回信息
    html = ''

    #payload
    payload_dict = {}
    error_dict = {}

    #最原始页面
    true_content = ''

    def __init__(self):
        # 非字符数字类型再这里重新声明下
        self.mark_flag = False
        # payload 有序字典，防止payload自动乱序
        self.payload_dict = OrderedDict()
        #报错字典
        self.error_dict = OrderedDict()
        self.read_xml_errors()

    # 匹配name=2&file=cc.xls&id=2 或者name=2&file=cc.xls，容易误判，比如price=2.6

    # 从xml中读取payload字典当中
    def read_xml_errors(self):
        DOMTree = xml.dom.minidom.parse(ERROR_DBMS_XML)
        collection = DOMTree.documentElement
        error_dict = OrderedDict()

        type_collection = collection.getElementsByTagName("type")
        for type_node in type_collection:
            type = str(type_node.getAttribute("value"))
            error_dict[type] = []
            payloads_node = type_node.getElementsByTagName('error')
            for payload_node in payloads_node:
                regexp = payload_node.getAttribute("regexp")
                error_dict[type].append(regexp)
        self.error_dict = error_dict

    #检测参数里面是否包含xx.xx?size=1 或者 xx.xx#fsdf 或者 xx.xx文件
    def check_value(self):
        if re.search(r'.*?\.\w+($|\?|#)',self.value):
            return True
        else:
            return False

    # 检测参数是否在敏感列表里面
    def check_param(self):
        if list(filter(lambda i:self.param in i,SENSITIVE_PARAM_LIST)):
            return True
        else:
            return False


    # 检查文件读取
    def check_sensitive_regexp(self):
        for type in self.error_dict:
            for regexp in  self.error_dict[type]:
                if re.search(regexp,self.html):
                    print("ERROR:##########################################check file read###################################")
                    return
        if re.search(self.regexp,self.html):
            print("FILE:##########################################check file read###################################")
            return



    # 发送请求包，并判断注入
    def send_request(self,req_info,type):
        if req_info['method'] == 'POST':
            try:
                # 显示参数和poc
                print(req_info[type])
                #这里allow_redirects禁止跟随是因为有些网站他会跳转到http://about:blank不是域名的地方导致异常
                rsp = requests.post(req_info['url'], data=req_info['data'], headers=req_info['headers'], proxies=g_proxy, timeout=TIMEOUT,verify=False, allow_redirects=False)
                return rsp
            except Exception:
                pass
        if req_info['method'] == 'GET':
            try:
                # 显示参数和poc
                print(req_info[type])
                rsp = requests.get(req_info['url'], headers=req_info['headers'], proxies=g_proxy, timeout=TIMEOUT, verify=False,allow_redirects=False)
                return rsp
            except Exception:
                pass


    # 对注入标记进行处理，判断注入
    def check_file_read(self,req_info,type):
        # print(req_info['headers'])

        # 这里兼容get和post，所以可能有些是none
        req_info['data'] = req_info['data'] if req_info['data'] != None else ""
        req_info['cookie'] = req_info['cookie'] if req_info['cookie'] != None else ""

        if SQLMARK in req_info['url'] or SQLMARK in req_info['data'] or SQLMARK in str(req_info['headers']):
            # 对url里面标记检查
            if SQLMARK in req_info['url']:
                insert_mark_list = re.finditer(SQLMARK,req_info['url'])
                for insert_mark_tuple in insert_mark_list:
                    for payload_type in self.payload_dict:
                        for payload in self.payload_dict[payload_type]:
                            # 深拷贝
                            req_poc_info = req_info.copy()

                            self.payload = payload[0]
                            self.regexp = payload[1]

                            # 这里对标记直接进行替换
                            req_poc_info['url'] = req_poc_info['url'][:insert_mark_tuple.regs[0][0]] + self.payload + req_poc_info['url'][insert_mark_tuple.regs[0][1]:]
                            rsp = self.send_request(req_poc_info, 'url')

                            self.html = rsp.content
                            self.check_sensitive_regexp()
            # 对data里面标记检查
            elif SQLMARK in req_info['data']:
                insert_mark_list = re.finditer(SQLMARK,req_info['data'])
                for insert_mark_tuple in insert_mark_list:
                    for payload_type in self.payload_dict:
                        for payload in self.payload_dict[payload_type]:
                            # 深拷贝
                            req_poc_info = req_info.copy()

                            self.payload = payload[0]
                            self.regexp = payload[1]

                            # 这里对标记直接进行替换
                            req_poc_info['data'] = req_poc_info['data'][:insert_mark_tuple.regs[0][0]] +  self.payload + req_poc_info['data'][insert_mark_tuple.regs[0][1]:]
                            rsp = self.send_request(req_poc_info, 'data')

                            self.html = rsp.content
                            self.check_sensitive_regexp()
            # 对headers和cookie里面标记检查
            elif SQLMARK in str(req_info['headers']):
                # 进行标记检查
                if SQLMARK in req_info['headers']['Cookie']:
                    insert_mark_list = re.finditer(SQLMARK, req_info['headers']['Cookie'])
                    for insert_mark_tuple in insert_mark_list:
                        for payload_type in self.payload_dict:
                            for payload in self.payload_dict[payload_type]:
                                # 深拷贝
                                req_poc_info = req_info.copy()
                                req_poc_info['headers'] = req_info['headers'].copy()

                                self.payload = payload[0]
                                self.regexp = payload[1]

                                # 这里对标记直接进行替换
                                req_poc_info['headers']['Cookie'] = req_poc_info['headers']['Cookie'][:insert_mark_tuple.regs[0][0]] + self.payload + req_poc_info['headers']['Cookie'][insert_mark_tuple.regs[0][1]:]
                                rsp = self.send_request(req_poc_info, 'headers')

                                self.html = rsp.content
                                self.check_sensitive_regexp()
                else:
                    # 循环headers
                    for header in req_info['headers']:
                        insert_mark_list = re.finditer(SQLMARK, req_info['headers'][header])
                        # 循环遍历标记
                        for insert_mark_tuple in insert_mark_list:
                            # 循环payload
                            for dbms in self.payload_dict:
                                for payload in self.payload_dict[dbms]:
                                    # header头是不会url解码的，所以对于headers进行解码
                                    self.payload = urllib.unquote(payload[0])
                                    self.regexp = payload[1]

                                    # 深拷贝
                                    req_poc_info = req_info.copy()
                                    # 这进行初始化是为了防止req_poc_info['headers'] 和 req_info['headers'] 变成同一个地址的东西，称呼不同
                                    req_poc_info['headers'] = req_poc_info['headers'].copy()
                                    req_poc_info['headers'][header] = req_info['headers'][header][:insert_mark_tuple.regs[0][0]] + self.payload + req_info['headers'][header][insert_mark_tuple.regs[0][1]:]

                                    rsp = self.send_request(req_poc_info, 'headers')
                                    self.html = rsp.content
                                    self.check_sensitive_regexp()
            exit()

        if not self.check_value() and not self.check_param():
            return
        if type == 'host':
            for type in self.payload_dict:
                for payload in self.payload_dict[type]:
                    # 直接检测host类型
                    if type != 'host':
                        continue

                    # 深拷贝
                    req_poc_info = req_info.copy()

                    self.payload = payload[0]
                    self.regexp = payload[1]

                    parse_url = urlparse.urlparse(req_info['url'])
                    req_poc_info['url'] = "%s://%s%s/%s" % (parse_url.scheme, parse_url.hostname, ':'+str(parse_url.port) if parse_url.port else '', payload[0])
                    req_poc_info['method'] = 'GET'

                    rsp = self.send_request(req_poc_info, 'url')
                    self.html = rsp.content
                    self.check_sensitive_regexp()
        if type == 'url':
            for type in self.payload_dict:
                for payload in self.payload_dict[type]:

                    # 深拷贝
                    req_poc_info = req_info.copy()

                    self.payload = payload[0]
                    self.regexp = payload[1]

                    if 'append_value' == type:
                        req_poc_info['url'] = req_poc_info['url'][:self.value_tuple[0]] + self.value + self.payload + req_poc_info['url'][self.value_tuple[1]:]
                    elif 'repleace_value' == type:
                        req_poc_info['url'] = req_poc_info['url'][:self.value_tuple[0]] + self.payload + req_poc_info['url'][self.value_tuple[1]:]
                    else:
                        continue
                    rsp = self.send_request(req_poc_info, 'url')

                    self.html = rsp.content
                    self.check_sensitive_regexp()
        elif type == 'body':
            for payload_type in self.payload_dict:
                for payload in self.payload_dict[payload_type]:
                    # 深拷贝
                    req_poc_info = req_info.copy()

                    self.payload = payload[0]
                    self.regexp = payload[1]

                    if 'append_value' == type:
                        req_poc_info['data'] = req_poc_info['data'][:self.value_tuple[0]] + self.value + self.payload + req_poc_info['data'][self.value_tuple[1]:]
                    elif 'repleace_value' == type:
                        req_poc_info['data'] = req_poc_info['data'][:self.value_tuple[0]] + self.payload + req_poc_info['data'][self.value_tuple[1]:]
                    else:
                        continue
                    rsp = self.send_request(req_poc_info, 'data')

                    self.html = rsp.content
                    self.check_sensitive_regexp()
        elif type == 'cookie':
            # 进行常规cookie检查
            for payload_type in self.payload_dict:
                for payload in self.payload_dict[payload_type]:
                    # 深拷贝
                    req_poc_info = req_info.copy()
                    req_poc_info['headers'] = req_poc_info['headers'].copy()

                    self.payload = payload[0]
                    self.regexp = payload[1]

                    req_poc_info['headers']['Cookie'] = req_poc_info['headers']['Cookie'][:self.value_tuple[0]] + req_poc_info['headers']['Cookie'][self.value_tuple[0]:self.value_tuple[1]] + self.payload + req_poc_info['headers']['Cookie'][self.value_tuple[1]:]
                    rsp = self.send_request(req_poc_info, 'headers')

                    self.html = rsp.content
                    self.check_sensitive_regexp()
        elif type == 'header':
            pass
            # for header in req_info['headers']:
            #     #过滤header白名单列表
            #     if header in WHITE_HEADER_LIST:
            #         continue
            #     #添加敏感header列表
            #     sensitive_header_dict = SENSITIVE_HEADER_DICT.copy()
            #     if sensitive_header_dict.has_key(header):
            #         sensitive_header_dict.pop(header)
            #
            #     for dbms in self.payload_dict:
            #         for payload in self.payload_dict[dbms]:
            #             # header头是不会url解码的，所以对于headers进行解码
            #             self.payload = urllib.unquote(payload[0])
            #             self.regexp = payload[1]
            #
            #             # 深拷贝
            #             req_poc_info = req_info.copy()
            #             # 这进行初始化是为了防止req_poc_info['headers'] 和 req_info['headers'] 变成同一个地址的东西，称呼不同
            #             req_poc_info['headers'] = req_poc_info['headers'].copy()
            #             req_poc_info['headers'][header] = req_info['headers'][header] + self.payload
            #
            #             rsp = self.send_request(req_poc_info, 'headers')
            #             self.html = rsp.content
            #             self.check_sensitive_regexp()
            # #添加原来header没有的敏感header
            # for header in sensitive_header_dict:
            #     for dbms in self.payload_dict:
            #         for payload in self.payload_dict[dbms]:
            #             # header头是不会url解码的，所以对于headers进行解码
            #             self.payload = urllib.unquote(payload[0])
            #             self.regexp = payload[1]
            #
            #             # 深拷贝
            #             req_poc_info = req_info.copy()
            #             # 这进行初始化是为了防止req_poc_info['headers'] 和 req_info['headers'] 变成同一个地址的东西，称呼不同
            #             req_poc_info['headers'] = req_poc_info['headers'].copy()
            #             req_poc_info['headers'][header] = sensitive_header_dict[header] + self.payload
            #
            #             rsp = self.send_request(req_poc_info, 'headers')
            #             self.html = rsp.content
            #             self.check_sensitive_regexp()