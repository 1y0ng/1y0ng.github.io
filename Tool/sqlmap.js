	function one(inputString) {
	  if (inputString.startsWith("http")) {
		return "u";
	  } else {
		return "r";
	  }
	}
  function generateSentence() {
    var select1 = document.getElementById("select1");
    var select2 = document.getElementById("select2");
    var select3 = document.getElementById("select3");
    var target = document.getElementById("target").value;
    var proxy = document.getElementById("proxy").value
    var option1 = one(target);
    var point = document.getElementById("point").value;
    var technique = document.getElementById("technique").value;
    var dbms = document.getElementById("dbms").value;
    // alert(option1);
    var resultElement = document.getElementById("result");
    if (!point) {
      point = "";  // 直接返回空字符串
    } else {
      point = "-p " + point;  // 在 point 前面加上 "-p"
    }

    var sentence = `python sqlmap.py -${option1} ${target}  ${point} --random-agent --proxy ${proxy} --risk=3 --level=5 --threads 10 ${technique} ${dbms}`;
    resultElement.textContent = sentence;
  }