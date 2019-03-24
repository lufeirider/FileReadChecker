# encoding=utf8
from parse import *
from common import *
from SqlChecker import *

requests.packages.urllib3.disable_warnings()

# sql注入的信息都在g_file_read_info里面
g_file_read_info = FileReadChecker()


req = '''
http://127.0.0.1/include.php?filename=c:/windows/win.ini
'''


# 解析数据包或者url
req_info = parseRequestFile(req) if parseRequestFile(req) else parse_url(req)

#添加user-agent，因为waf真的从这个判断恶意请求
if not req_info['headers'].has_key("User-Agent"):
    req_info['headers']['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21'

#检测是否是https
if check_https(req_info) == True:
    SSLFLAG = True
    parse_url = urlparse.urlparse(req_info['url'])
    req_info['url'] = "%s://%s:%s%s%s%s" % ("https", parse_url.hostname, "443", parse_url.path, "?" + parse_url.query if parse_url.query else "","#" + parse_url.fragment if parse_url.fragment else "")

#获取正确页面
g_file_read_info.true_content = get_right_resp(req_info)

# 加载payload 到 g_file_read_info.payload_dict
g_file_read_info.payload_dict = read_xml_payloads()

# host 检测
g_file_read_info.check_file_read(req_info,'host')

# cookie检测
if req_info['cookie'] != '':
    param_tuple = re.finditer(r'(\S*?)=(\S*?)(;|$)', req_info['cookie'])
    for param in param_tuple:
        g_file_read_info.param = param.group(1)
        g_file_read_info.param_tuple = param.regs[1]
        g_file_read_info.value = param.group(2)
        g_file_read_info.value_tuple = param.regs[2]
        g_file_read_info.check_file_read(req_info,'cookie')

#POST检测
if req_info['method'] == 'POST':
    #multipart
    if re.search(MULTIPART_REGEX, req_info['data']):
        param_tuple = re.finditer(r"(?si)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>[^\"'\r\n]+)[\"']?)((\r)?\n){2}(.*?))(((\r)?\n)+--)", req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            g_file_read_info.param = param.group(3)
            g_file_read_info.param_tuple = param.regs[3]
            g_file_read_info.value = param.group(6)
            g_file_read_info.value_tuple = param.regs[6]
            g_file_read_info.check_sql(req_poc_info, 'body')
        exit()
    # json
    elif re.search(JSON_REGEX, req_info['data']):
        # 字符型
        param_tuple = re.finditer(r'"(?P<name>[^"]+)"\s*:\s*"(.*?)"(?<!\\")', req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            g_file_read_info.param = param.group(1)
            g_file_read_info.param_tuple = param.regs[1]
            g_file_read_info.value = param.group(2)
            g_file_read_info.value_tuple = param.regs[2]
            g_file_read_info.check_sql(req_poc_info, 'body')
        # 数字型 要把数字型加上双引号，不然没办法添加payload
        param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            g_file_read_info.param = param.group(1)
            g_file_read_info.param_tuple = param.regs[1]
            g_file_read_info.value = param.group(2)
            g_file_read_info.value_tuple = param.regs[2]
            g_file_read_info.check_sql(req_poc_info, 'body')
        exit()
    # xml类型
    elif re.search(XML_REGEX, req_info['data']):
        param_tuple = re.finditer(r"(<(?P<name>[^>]+)( [^<]*)?>)([^<]+)(</\2)", req_info['data'])
        for param in param_tuple:
            req_poc_info = req_info.copy()
            g_file_read_info.param = param.group(2)
            g_file_read_info.param_tuple = param.regs[2]
            g_file_read_info.value = param.group(4)
            g_file_read_info.value_tuple = param.regs[4]
            g_file_read_info.check_sql(req_poc_info, 'body')
        exit()

    # post 中data参数存在注入
    param_tuple = re.finditer(r'(.*?)=(.*?)(&|$)', req_info['data'])
    for param in param_tuple:
        req_poc_info = req_info.copy()
        g_file_read_info.param = param.group(1)
        g_file_read_info.param_tuple = param.regs[1]
        g_file_read_info.value = param.group(2)
        g_file_read_info.value_tuple = param.regs[2]
        json_value = req_info['data'][param.regs[2][0]:param.regs[2][1]]
        if re.search(JSON_REGEX, json_value):
            # 字符型
            param_tuple = re.finditer(r'"(?P<name>[^"]+)"\s*:\s*"(.*?)"(?<!\\")', req_info['data'])
            for param in param_tuple:
                req_poc_info = req_info.copy()
                g_file_read_info.param = param.group(1)
                g_file_read_info.param_tuple = param.regs[1]
                g_file_read_info.value = param.group(2)
                g_file_read_info.value_tuple = param.regs[2]
                g_file_read_info.check_sql(req_poc_info, 'body')
            # 数字型 要把数字型加上双引号，不然没办法添加payload
            param_tuple = re.finditer(r'("(?P<name>[^"]+)"\s*:\s*)(-?\d[\d\.]*)\b', req_info['data'])
            for param in param_tuple:
                req_poc_info = req_info.copy()
                g_file_read_info.param = param.group(1)
                g_file_read_info.param_tuple = param.regs[1]
                g_file_read_info.value = param.group(2)
                g_file_read_info.value_tuple = param.regs[2]
                g_file_read_info.check_sql(req_poc_info, 'body')
        else:
            g_file_read_info.check_file_read(req_poc_info, 'body')
    # post中url参数存在注入
    parse_url = urlparse.urlparse(req_info['url'])
    offset = req.index(parse_url.query)
    param_tuple = re.finditer(r'(.*?)=(.*?)(&|$)', parse_url.query)
    for param in param_tuple:
        g_file_read_info.param = param.group(1)
        g_file_read_info.param_tuple = (offset + param.regs[1][0],offset + param.regs[1][1])
        g_file_read_info.value = param.group(2)
        g_file_read_info.value_tuple = (offset + param.regs[2][0],offset + param.regs[2][1])
        g_file_read_info.check_file_read(req_info, 'url')
    exit()

#url get注入检测
if req_info['method'] == 'GET':
    parse_url = urlparse.urlparse(req_info['url'])
    offset = req_info['url'].index(parse_url.query)
    param_tuple = re.finditer(r'(.*?)=(.*?)(&|$)', parse_url.query)
    for param in param_tuple:
        g_file_read_info.param = param.group(1)
        g_file_read_info.param_tuple = (offset + param.regs[1][0],offset + param.regs[1][1])
        g_file_read_info.value = param.group(2)
        g_file_read_info.value_tuple = (offset + param.regs[2][0],offset + param.regs[2][1])
        g_file_read_info.check_file_read(req_info, 'url')
    exit()