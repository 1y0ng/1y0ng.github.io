
function make_python_code(){
	var org_message = document.getElementById("org_message").value;
    let post_data = "";
    let rawRequest = "";
    let is_POST = false;
    if (org_message.startsWith("POST")) {
        is_POST = true;
        post_data = org_message.split("\n\n")[1];
        rawRequest = org_message.split("\n\n")[0];
    }else{
        rawRequest = org_message;
    }
    // 分割请求行和头部
    const lines = rawRequest.trim().split('\n');
    console.log(rawRequest)
    const requestLine = lines[0].trim();
    const headers = lines.slice(1).map(line => line.trim());
    
    // 解析请求方法和URL
    const requestParts = requestLine.split(' ');
    const method = requestParts[0];
    let url = requestParts[1];
	
	let head = "headers={"
    // 添加头部信息
    headers.forEach(header => {
        if (header) {
            let h = header.split(':');
			let k = h[0];
			let v = h.slice(1).join(":");
            if (k=="Host"){
                url = "http://"+v.slice(1)+url;
            }else{
                if (k!="Content-Length"){
                    head += `'${k}': '${v}',\n`;
                }
            }

        }
    });
    head += "}\n";

    let post_k = "data";
    if (is_POST){
        if (post_data[0]=="{" || post_data[0]=="["){
            post_k = "json";
            post_v = `data = ${post_data}\n`
        }else{
            post_v = `data = "${post_data}"\n`
        }
    }else{
        post_v = ""
    }

    // 构建Python的requests代码
    let pythonCode = `import requests\n\n`;
    pythonCode += `requests.packages.urllib3.disable_warnings()\n\n`
    pythonCode += head;
    pythonCode += post_v;
    if(is_POST){
        pythonCode += `response = requests.${method.toLowerCase()}('${url}',headers = headers,data = data)\n`;
    }else{
        pythonCode += `response = requests.${method.toLowerCase()}('${url}',headers = headers)\n`;
    }
    
    pythonCode += `# 响应状态码\nprint(response.status_code)\n`;
    pythonCode += `# 响应内容\nprint(response.text)\n`;

    var python_code = document.getElementById("python_code");
    python_code.textContent = pythonCode;
}

function copyToClipboard() {
    var text = document.getElementById("python_code").value;
    console.log(text);
    navigator.clipboard.writeText(text)
      .then(function() {
        console.log("文本已成功复制到剪切板");
        alert("文本已成功复制到剪切板");
      })
      .catch(function(error) {
        console.error("复制文本时出现错误:", error);
      });
}