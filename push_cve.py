import os
import json
import datetime
import requests
import urllib.parse
from xml.dom.minidom import parse


class Monitor:
    def __init__(self, webhook, ak, sk) -> None:
        self.webhook = webhook  # 推送的地址
        self.ak = ak  # 某度翻译平台的校验参数
        self.sk = sk  # 某度翻译平台的校验参数
        self.__access_token = ""  # 调用某度翻译接口的必要参数
        self.__valid_cve_info = {}  # 新增cve信息
        self.__xml_file = "temp.xml"  # 从cve官网下载的cve信息合集
        self.__json_file = "cve_info.json"  # 文件名，解析后的cve信息会保存在和此py文件同一目录
        self.__json_tmp_file = "cve_info_tmp.json" # 临时文件名
        self.__header = {"Content-Type": "application/json"}  # 推送的请求头
        self.__cve_url = "https://cve.mitre.org/data/downloads/allitems-cvrf-year-2023.xml"  # cve官网文件，cve信息来源

    # 下载cve官网文件，官网文件的格式为xml
    def __download(self):
        resp = requests.get(self.__cve_url)
        with open(self.__xml_file, "w", encoding="utf-8") as fp:
            fp.write(resp.text)

    # 将xml文件解析成json格式，并写入文件
    def __xml_to_json(self):
        self.__download()
        # 解析xml，获取根节点，然后进一步获取Vulnerability节点
        doc = parse(self.__xml_file)
        root = doc.documentElement
        vul_tag = root.getElementsByTagName("Vulnerability")
        # 遍历所有Vulnerability节点，通过节点下的其他节点来筛选出合格的cve，并添加到list中
        for i in vul_tag:
            description = i.getElementsByTagName("Notes")[0].getElementsByTagName("Note")[0].firstChild.data
            if "This candidate has been reserved" not in description:
                cve_number = i.getElementsByTagName("CVE")[0].firstChild.data
                try:
                    cve_url = \
                        i.getElementsByTagName("References")[0].getElementsByTagName("Reference")[
                            0].getElementsByTagName(
                            "URL")[0].firstChild.data
                except Exception as e:
                    continue
                else:
                    self.__valid_cve_info[cve_number] = {"description": description, "url": cve_url}
        # 看是否存在已解析好的json文件，存在则创建新的临时文件
        if os.path.exists(self.__json_file):
            with open(self.__json_tmp_file, "w", encoding="utf-8") as fp:
                fp.write(json.dumps(self.__valid_cve_info, indent=4))
        else:
            with open(self.__json_file, "w", encoding="utf-8") as fp:
                fp.write(json.dumps(self.__valid_cve_info, indent=4))
        os.remove(self.__xml_file)

    # 对比文件是否有新增
    def __compare(self, older_cve_info: dict) -> dict:
        new_message = {}
        for key in self.__valid_cve_info.keys():
            if key not in older_cve_info:
                new_message[key] = self.__valid_cve_info[key]
        return new_message

    # 推送的具体实现
    def __send(self, new_message: dict):
        for k, v in new_message.items():
            # 翻译语句
            sentence = v["description"]
            translated_sentence = self.__translate(sentence)
            # 此处推送的格式为markdown，可以自行设置推送的格式
            md_data = {
                "msgtype": "markdown",
                "markdown": {
                    "title": "新增CVE推送",
                    "text": f"## 新增CVE推送  \n  > **CVE编号:** {k}  \n  **漏洞地址:** {v['url']}  \n  **漏洞描述:** {sentence}({translated_sentence}）"
                }
            }
            data = json.dumps(md_data)
            res = requests.post(url=self.webhook, headers=self.__header, data=data)
            if "ok" in res.text:
                print("推送成功，已推送:", k, datetime.datetime.now())

    # 推送成功后的删除操作
    def __del_file(self):
        os.remove(self.__json_file)
        os.rename(self.__json_tmp_file, self.__json_file)

    # 翻译推送的信息
    def __translate(self, sentence: str) -> str:
        if self.__access_token == "":
            # 请求百度接口获取access_token
            url = "https://aip.baidubce.com/oauth/2.0/token?"
            url_params = {
                "grant_type": "client_credentials",
                "client_id": self.ak,
                "client_secret": self.sk
            }
            url = url + urllib.parse.urlencode(url_params)
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            payload = ""
            res = requests.post(url=url, headers=headers, data=payload).text
            self.__access_token = json.loads(res)["access_token"]
        # 请求百度AI翻译接口进行翻译
        api_url = "https://aip.baidubce.com/rpc/2.0/mt/texttrans/v1?access_token=" + self.__access_token
        headers = {
            "Content-type": "application/json;charset=utf-8"
        }
        # 此处固定为英译中，可以自行设置翻译类型
        payload = {
            "q": sentence,
            "from": "en",
            "to": "zh",
        }
        resp = requests.post(url=api_url, headers=headers, data=json.dumps(payload))
        translated_word = json.loads(resp.text)["result"]["trans_result"][0]["dst"]
        return translated_word

    # 开始运行
    def start(self):
        self.__xml_to_json()
        if os.path.exists(self.__json_tmp_file):
            with open(self.__json_file, "r") as fp:
                older_cve_info = json.loads(fp.read())
            new_message = self.__compare(older_cve_info)
            if new_message:
                self.__send(new_message)
            else:
                print("暂无新增CVE", datetime.datetime.now(), "\n")
            self.__del_file()
        else:
            print("暂无新增CVE", datetime.datetime.now(), "\n")


if __name__ == '__main__':
    webhook = ""
    ak = ""
    sk = ""
    monitor = Monitor(webhook=webhook,ak=ak,sk=sk)
    monitor.start()
