# push-cve 新增cve的自动推送

> 1. 文中推送使用的是某钉的自定义机器人，若使用其他软件，可自行查找相关的官方文档修改代码中的参数进行推送
> 
> 2. 文中使用了付费的某度翻译接口，可自行修改翻译的接口参数以达到相同功能，也可去直接除掉翻译功能(有助于英语能力提高)
> 
> 3. 设置定时任务(如:crontab)来运行该文件，以保证能够实时推送
> 
>    示例: ```0 */4 * * * cd /xxx/xxx && python3 push-cve.py >> log.txt ```  => 意为每4小时运行一次，并记录相关日志
>
>    **注意:**  因为会在py文件的同一目录下生成、修改和删除相关的文件，定时任务的命令必须加上切换到py文件所在目录的命令
> 
**推送的消息格式大致如下:**
#### 新增cve推送
> CVE编号: CVE-2023-XXX
>
> 漏洞地址: https://xxx.xxx.com
>
> 漏洞描述: This is a description for CVE-2023-xxx.(漏洞描述的翻译)


