import requests

requests.packages.urllib3.disable_warnings()
headers={'Accept': ' text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
'Accept-Encoding': ' gzip, deflate',
'Accept-Language': ' zh-CN,zh;q=0.9',
'Cache-Control': ' max-age=0',
'Connection': ' keep-alive',
'Cookie': ' language=zh-CN; cr_jwttoken=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ImRlYzEyMmU3N2U4MTQ1YjJhZWVlZmI5NTc2NTdkYWM5IiwiZXhwIjoxNzMyOTI0MzkwLCJrZXkiOiI3N2IwYThjZDRlOWI0YmI3YmI4MjExMWYzZmE0ZGMzZSIsInVzZXJuYW1lIjoiQkhUNDFVMyJ9.zBw3Izq3eYUC-lahGlqgef0pGjqwEftbNwyltD1zNlg',
'Upgrade-Insecure-Requests': ' 1',
'User-Agent': ' Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
}
response = requests.get('http://10.10.6.1/page/mg/ct/wd/arena',headers = headers)
# 响应状态码
print(response.status_code)
# 响应内容
print(response.text)
